/*
In-process tests of the shim's connection logic.

`pytests/test_shim.py` runs the built `libssl.so` under `LD_PRELOAD`
inside real `curl` and `wget` against a real OpenSSL origin, and that
is the only thing that proves the interposition works. What it cannot
do is make the transport misbehave on demand: loopback never blocks a
write of a few kilobytes, never delivers a flight one byte at a time,
and the origin never corrupts a record or hangs up without a
close_notify. Every path through `SSL_read` and `SSL_write` that
handles one of those was therefore unexercised, and three of them were
wrong.

These tests drive the same `Connection` the entry points lock, over
`Transport::Scripted`, against this library's own `ServerConnection`.
Both ends are ours, so nothing here settles a byte order or a key
schedule - `tests/test_tls13_transcript.rs` and the pytest suites do
that. What it settles is what the shim *does* with what the record
layer tells it.
*/

use std::sync::{Arc, Mutex};

use allcrypt::bignum::BigUint;
use allcrypt::ec::curves;
use allcrypt::tls::server::{ServerConfig, ServerConnection, ServerKey};
use allcrypt::tls::Version;
use allcrypt::x509::builder::{key_usage, CertificateBuilder, SanEntry,
                              SigningKey, SubjectKey};
use allcrypt::x509::oids;

use crate::config::Settings;
use crate::state::{Connection, Context, Scripted, Transport};
use crate::*;

/// A root, and a leaf for `leaf.test` signed by it, on P-256.
struct Pki {
    root_der: Vec<u8>,
    leaf_der: Vec<u8>,
    leaf_private: BigUint,
}

fn pki() -> Pki {
    let curve = curves::p256();
    let (root_private, root_public) = curve.generate_key_pair().unwrap();
    let root_point = curve.encode_point(&root_public, false).unwrap();
    let (leaf_private, leaf_public) = curve.generate_key_pair().unwrap();
    let leaf_point = curve.encode_point(&leaf_public, false).unwrap();

    let mut root = CertificateBuilder::new(
        "Test Root", SubjectKey::Ec { curve: &curve, point: &root_point });
    root.is_ca = Some((true, None));
    root.key_usage = Some(key_usage::KEY_CERT_SIGN);
    let root_der = root.sign(&SigningKey::Ec { curve: &curve,
                                               private: &root_private })
        .unwrap();

    let mut leaf = CertificateBuilder::new(
        "leaf.test", SubjectKey::Ec { curve: &curve, point: &leaf_point });
    leaf.serial = vec![2];
    leaf.issuer = vec![(oids::COMMON_NAME, "Test Root".to_string())];
    leaf.key_usage = Some(key_usage::DIGITAL_SIGNATURE);
    leaf.extended_key_usage = vec![oids::EKU_SERVER_AUTH];
    leaf.sans = vec![SanEntry::Dns("leaf.test".to_string())];
    let leaf_der = leaf.sign(&SigningKey::Ec { curve: &curve,
                                               private: &root_private })
        .unwrap();

    Pki { root_der, leaf_der, leaf_private }
}

fn new_server(pki: &Pki) -> ServerConnection {
    let config = ServerConfig::new(
        vec![pki.leaf_der.clone()],
        ServerKey::Ec { curve: "P-256", private: pki.leaf_private.clone() });
    ServerConnection::new(config).unwrap()
}

/// A context as `SSL_CTX_new` makes one, with the test root loaded as
/// `SSL_CTX_load_verify_locations` would load it.
fn context(pki: &Pki) -> Arc<Mutex<Context>> {
    let settings = Arc::new(Settings::default());
    let mut context = Context::new(settings);
    context.roots.add_der(&pki.root_der).unwrap();
    context.roots_loaded = true;
    Arc::new(Mutex::new(context))
}

/// A connection as `SSL_new` plus `SSL_set_tlsext_host_name` leave one,
/// over a scripted transport.
fn connection(context: &Arc<Mutex<Context>>) -> Connection {
    let settings = Arc::clone(&context.lock().unwrap().settings);
    let mut connection = Connection::new(Arc::clone(context), settings);
    connection.hostname = Some("leaf.test".to_string());
    connection.transport = Transport::Scripted(Scripted::new());
    connection
}

fn script(inner: &mut Connection) -> &mut Scripted {
    match &mut inner.transport {
        Transport::Scripted(script) => script,
        _ => panic!("the connection is not on a scripted transport"),
    }
}

/// Carry what the shim wrote to the server, and the server's answer
/// back as one chunk. Says whether anything moved.
fn exchange(inner: &mut Connection, server: &mut ServerConnection) -> bool {
    let to_server = std::mem::take(&mut script(inner).written);
    if !to_server.is_empty() {
        server.push_incoming(&to_server);
        server.process().expect("the server rejected the shim");
    }
    let to_client = server.take_outgoing();
    let moved = !to_server.is_empty() || !to_client.is_empty();
    if !to_client.is_empty() {
        script(inner).incoming.push_back(to_client);
    }
    moved
}

/// Drive `handshake` to completion against the server.
fn connect(inner: &mut Connection, server: &mut ServerConnection) {
    for _ in 0..12 {
        match handshake(inner) {
            Ok(true) => {
                // The shim's last flight is still in the script.
                exchange(inner, server);
                assert!(server.is_established(), "server: {}", server.state());
                return;
            }
            Ok(false) => {
                assert_eq!(inner.last_error, SSL_ERROR_WANT_READ);
                assert!(exchange(inner, server), "the handshake stalled");
            }
            Err(reason) => panic!("the handshake failed: {}", reason),
        }
    }
    panic!("the handshake did not settle in twelve exchanges");
}

/// `SSL_read` into a buffer, on a connection already locked.
fn read(inner: &mut Connection, length: usize) -> (c_int, Vec<u8>) {
    let mut buffer = vec![0u8; length];
    let result = read_locked(inner, &mut buffer, false);
    if result > 0 {
        buffer.truncate(result as usize);
    } else {
        buffer.clear();
    }
    (result, buffer)
}

// ------------------------------------------------------------- handshake ---

/// A TLS alert record in the clear: `level`, `description`.
fn alert_record(level: u8, description: u8) -> Vec<u8> {
    vec![0x15, 0x03, 0x03, 0x00, 0x02, level, description]
}

/// A server that answers the ClientHello with close_notify has not
/// completed a handshake, and `SSL_connect` must say so.
///
/// What was wrong: the handshake loop left on `!is_handshaking()`,
/// which is true of `Closed` and `Failed` as well as `Established`,
/// and then set `established` after the same check. A close_notify in
/// answer to the hello put the record layer in `Closed` with `Ok`, the
/// shim declared the handshake finished, and - with `SSL_VERIFY_NONE`,
/// as `curl -k` sets - `finish` had nothing to refuse, so the program
/// was told the connection was up and read nothing from it. No pytest
/// origin closes during a handshake, so the path was never taken.
#[test]
fn a_close_notify_during_the_handshake_is_a_failure() {
    let pki = pki();
    let context = context(&pki);
    let mut inner = connection(&context);

    assert_eq!(handshake(&mut inner), Ok(false));
    assert_eq!(inner.last_error, SSL_ERROR_WANT_READ);
    assert!(!script(&mut inner).written.is_empty(), "no ClientHello went out");

    // close_notify is a warning-level alert with description 0.
    script(&mut inner).incoming.push_back(alert_record(1, 0));
    let outcome = handshake(&mut inner);
    assert!(matches!(&outcome, Err(reason) if reason.contains("closed")),
            "a close_notify in answer to the hello gave {:?}", outcome);
    assert!(!inner.established, "the connection was marked established");
}

/// A server flight that arrives one byte at a time still completes.
///
/// What was wrong: the handshake loop was capped at 64 rounds, with
/// one read per round, so a peer whose flight arrived in more than 64
/// segments - a server certificate of a few kilobytes over a link that
/// delivers small segments, which the old equipment this shim exists
/// for does - was refused with "the handshake did not settle" while it
/// was arriving perfectly well. Loopback in `pytests/test_shim.py`
/// delivers a flight in one or two reads, so the cap was never reached
/// there. The loop is now bounded by bytes received, which bounds a
/// peer that never settles without refusing one that is slow.
#[test]
fn a_flight_delivered_one_byte_at_a_time_completes() {
    let pki = pki();
    let mut server = new_server(&pki);
    let context = context(&pki);
    let mut inner = connection(&context);

    for _ in 0..12 {
        match handshake(&mut inner) {
            Ok(true) => {
                exchange(&mut inner, &mut server);
                assert!(server.is_established());
                assert!(inner.established);
                return;
            }
            Ok(false) => {
                let to_server = std::mem::take(&mut script(&mut inner).written);
                if !to_server.is_empty() {
                    server.push_incoming(&to_server);
                    server.process().unwrap();
                }
                let flight = server.take_outgoing();
                assert!(!flight.is_empty(), "the handshake stalled");
                assert!(flight.len() > 64,
                        "a flight of {} bytes cannot exceed a 64-read cap",
                        flight.len());
                for byte in flight {
                    script(&mut inner).incoming.push_back(vec![byte]);
                }
            }
            Err(reason) => panic!("the handshake failed: {}", reason),
        }
    }
    panic!("the handshake did not settle");
}

/// A second `SSL_connect` after a failed one fails again.
///
/// Same defect as above, through `Failed`: the record layer refused
/// the first time and `process` reported it, but the connection object
/// stayed, and the next call found it "not handshaking" and declared
/// it established.
#[test]
fn a_connect_after_a_failed_handshake_fails_again() {
    let pki = pki();
    let context = context(&pki);
    let mut inner = connection(&context);

    assert_eq!(handshake(&mut inner), Ok(false));
    // A fatal handshake_failure (level 2, description 40).
    script(&mut inner).incoming.push_back(alert_record(2, 40));
    assert!(handshake(&mut inner).is_err());
    assert!(!inner.established);

    let again = handshake(&mut inner);
    assert!(matches!(&again, Err(reason) if reason.contains("handshake_failure")),
            "a retry after a fatal alert gave {:?}", again);
    assert!(!inner.established, "a failed connection became established on retry");
}

/// A connection as `SSL_new` hands it to the program, so the entry
/// points that take an `SSL *` can be called on it. Freed with
/// `SSL_free`.
fn boxed(inner: Connection) -> *mut c_void {
    Box::into_raw(Box::new(SslHandle {
        inner: Mutex::new(inner),
        references: AtomicUsize::new(1),
    })) as *mut c_void
}

// ------------------------------------------------------- what was got ---

/// `SSL_CIPHER_get_name` hands out the same pointer every time.
///
/// What was wrong: the name was rebuilt with `format!` on every call
/// and assigned over the previous string, which freed the buffer a
/// pointer from the previous call still pointed into. A program that
/// kept the first pointer - the contract allows it - and asked again
/// read freed memory. `curl` and `wget` each ask once per connection,
/// so the second call never happened in the pytest runs.
#[test]
fn the_cipher_name_pointer_stays_valid_across_calls() {
    let pki = pki();
    let mut server = new_server(&pki);
    let context = context(&pki);
    let mut inner = connection(&context);
    connect(&mut inner, &mut server);
    let expected = inner.inner.as_ref().unwrap().negotiated_suite().unwrap()
        .openssl_name.to_string();

    let ssl = boxed(inner);
    unsafe {
        let cipher = SSL_get_current_cipher(ssl);
        assert!(!cipher.is_null());
        let first = SSL_CIPHER_get_name(cipher);
        let second = SSL_CIPHER_get_name(cipher);
        assert_eq!(first, second, "the name moved between two calls");
        assert_eq!(std::ffi::CStr::from_ptr(first).to_str().unwrap(), expected);
        SSL_free(ssl);
    }
}

/// `SSL_get_verify_result` on nothing is not `X509_V_OK`.
///
/// What was wrong: a null handle, or a poisoned lock, was answered
/// with `X509_V_OK`, so a program that reached this with a bad pointer
/// was told its peer had verified. Nothing in the pytest runs passes a
/// null `SSL *`, and a verdict is only ever asked of a live
/// connection there.
#[test]
fn the_verify_result_of_no_connection_is_not_ok() {
    let result = unsafe { SSL_get_verify_result(std::ptr::null_mut()) };
    assert_ne!(result, X509_V_OK, "a null connection was reported as verified");
    assert_eq!(result, X509_V_ERR_UNSPECIFIED);

    // And a real verdict still comes through: the test root was loaded,
    // so a finished connection verifies.
    let pki = pki();
    let mut server = new_server(&pki);
    let context = context(&pki);
    let mut inner = connection(&context);
    connect(&mut inner, &mut server);
    let ssl = boxed(inner);
    unsafe {
        assert_eq!(SSL_get_verify_result(ssl), X509_V_OK);
        SSL_free(ssl);
    }
}

// ---------------------------------------------------------- NULL suites ---

/// A NULL suite is reachable by default, and negotiating one is said
/// whatever the verbosity.
///
/// What was wrong: the default offer includes the NULL suites, by
/// `config.rs`'s argument that a shim must not narrow what was asked
/// for, and a server that picked one gave a connection with no
/// encryption that the program reported as TLS - with nothing printed
/// unless `ALLCRYPT_VERBOSE` was set. The default is kept; the line is
/// not optional any more. The pytest origins run at OpenSSL's default
/// security level, which offers no NULL suite, so none was ever
/// negotiated there.
#[test]
fn a_null_suite_is_reached_by_default_and_warned_about() {
    use allcrypt::publickey_ciphers::rsa::RsaPrivateKey;
    use allcrypt::tls::suites::Selection;

    // NULL suites are RSA key transport, so the server needs an RSA
    // key: small, because a prime search runs on every `cargo test`.
    let key = RsaPrivateKey::generate(1024).unwrap();
    let public = key.public_key();
    let mut leaf = CertificateBuilder::new(
        "leaf.test", SubjectKey::Rsa { n: &public.n, e: &public.e });
    leaf.serial = vec![3];
    leaf.is_ca = Some((true, None));
    leaf.extended_key_usage = vec![oids::EKU_SERVER_AUTH];
    leaf.sans = vec![SanEntry::Dns("leaf.test".to_string())];
    let leaf_der = leaf.sign(&SigningKey::Rsa(&key)).unwrap();

    let mut config = ServerConfig::new(vec![leaf_der.clone()],
                                       ServerKey::Rsa(Box::new(key)));
    config.suites = Selection::named(&["TLS_RSA_WITH_NULL_SHA"]).unwrap();
    // A 1.2 suite; the server has to be willing to stay there.
    config.max_version = Version::TLS12;
    let mut server = ServerConnection::new(config).unwrap();

    let settings = Arc::new(Settings::default());
    let mut trusting = Context::new(settings);
    trusting.roots.add_der(&leaf_der).unwrap();
    trusting.roots_loaded = true;
    let null_context = Arc::new(Mutex::new(trusting));
    let mut inner = connection(&null_context);
    connect(&mut inner, &mut server);

    let suite = inner.inner.as_ref().unwrap().negotiated_suite().unwrap();
    assert_eq!(suite.name, "TLS_RSA_WITH_NULL_SHA",
               "the default offer no longer reaches a NULL suite");
    let warning = insecure_suite_warning(suite)
        .expect("a NULL suite was negotiated without a warning");
    assert!(warning.contains("TLS_RSA_WITH_NULL_SHA"), "{}", warning);
    assert!(warning.contains("in the clear"), "{}", warning);

    // And a suite that encrypts gets no such line.
    let pki = pki();
    let mut server = new_server(&pki);
    let mut inner = connection(&context(&pki));
    connect(&mut inner, &mut server);
    let suite = inner.inner.as_ref().unwrap().negotiated_suite().unwrap();
    assert_eq!(insecure_suite_warning(suite), None, "{}", suite.name);
}

// ------------------------------------------------------------------ ALPN ---

/// The protocols a program sets are offered, and the server's choice
/// is what `SSL_get0_alpn_selected` reports.
///
/// What was wrong: `SSL_CTX_set_alpn_protos` stored the list and
/// nothing read it - `start` never set `ClientConfig::alpn` and
/// `SSL_get0_alpn_selected` always answered "none" - so a program's
/// request was accepted and dropped. Harmless against the pytest
/// origins, which negotiate no protocol, and so invisible there.
#[test]
fn alpn_protocols_are_offered_and_the_choice_is_reported() {
    let pki = pki();
    let mut server_config = ServerConfig::new(
        vec![pki.leaf_der.clone()],
        ServerKey::Ec { curve: "P-256", private: pki.leaf_private.clone() });
    // The server's order decides, so listing the two the other way
    // round at the client is what shows the offer reached it.
    server_config.alpn = vec!["h2".to_string(), "http/1.1".to_string()];
    let mut server = ServerConnection::new(server_config).unwrap();

    let context = context(&pki);
    context.lock().unwrap().alpn = b"\x08http/1.1\x02h2".to_vec();
    let mut inner = connection(&context);
    connect(&mut inner, &mut server);
    assert_eq!(inner.alpn_selected.as_deref(), Some(&b"h2"[..]),
               "the server's choice was not recorded");

    let ssl = boxed(inner);
    unsafe {
        let mut data: *const c_uchar = std::ptr::null();
        let mut length: c_uint = 0;
        SSL_get0_alpn_selected(ssl, &mut data, &mut length);
        assert_eq!(length, 2);
        assert_eq!(std::slice::from_raw_parts(data, 2), b"h2");
        SSL_free(ssl);
    }

    // A malformed list is refused, as OpenSSL refuses it, and the
    // earlier list stays. Non-zero is failure for this one function.
    unsafe {
        let ctx = SSL_CTX_new(TLS_client_method());
        let good = b"\x02h2";
        assert_eq!(SSL_CTX_set_alpn_protos(ctx, good.as_ptr(), good.len() as c_uint), 0);
        let bad = b"\x05h2";
        assert_eq!(SSL_CTX_set_alpn_protos(ctx, bad.as_ptr(), bad.len() as c_uint), 1);
        assert_eq!(ctx_of(ctx).unwrap().inner.lock().unwrap().alpn, good);
        SSL_CTX_free(ctx);
    }
    assert_eq!(alpn_names(b"\x02h2\x08http/1.1"),
               Some(vec!["h2".to_string(), "http/1.1".to_string()]));
    assert_eq!(alpn_names(b"\x00"), None);
    assert_eq!(alpn_names(b""), Some(Vec::new()));
}

// ------------------------------------------------------ the size_t forms ---

/// `SSL_read_ex` and `SSL_write_ex` clamp a `size_t` to what the `int`
/// forms can carry, and always write their count.
///
/// What was wrong: `length as c_int` turned any length of 2^31 or more
/// into a negative number or its low bits, so the inner call returned 0
/// and the `_ex` form reported failure with `*read` or `*written` left
/// holding whatever the caller had there. OpenSSL clamps. No program in
/// `pytests/test_shim.py` reads with a buffer that large, and none
/// reads the count after a failure, so neither showed.
#[test]
fn the_size_t_forms_clamp_and_always_write_the_count() {
    assert_eq!(clamp_length(0), 0);
    assert_eq!(clamp_length(4096), 4096);
    assert_eq!(clamp_length(c_int::MAX as usize), c_int::MAX);
    assert_eq!(clamp_length(1 << 31), c_int::MAX,
               "2^31 wrapped rather than clamped");
    assert_eq!(clamp_length(usize::MAX), c_int::MAX);

    // On failure the count is zero, not what was there before.
    let mut buffer = [0u8; 16];
    let mut read = 77usize;
    let result = unsafe {
        SSL_read_ex(std::ptr::null_mut(), buffer.as_mut_ptr() as *mut c_void,
                    buffer.len(), &mut read)
    };
    assert_eq!(result, 0);
    assert_eq!(read, 0, "a failed SSL_read_ex left the count unset");

    let mut written = 77usize;
    let result = unsafe {
        SSL_write_ex(std::ptr::null_mut(), buffer.as_ptr() as *const c_void,
                     buffer.len(), &mut written)
    };
    assert_eq!(result, 0);
    assert_eq!(written, 0, "a failed SSL_write_ex left the count unset");
}

// --------------------------------------------------------- cipher strings ---

/// A cipher string the program passes is reported whether or not the
/// shim is verbose, and kept on the context.
///
/// What was wrong: `SSL_CTX_set_cipher_list` returned success and
/// mentioned the substitution only under `ALLCRYPT_VERBOSE`, while the
/// file's own policy says nothing security-relevant is skipped quietly.
/// `curl --ciphers ECDHE-RSA-AES256-GCM-SHA384` was answered with
/// `ALLCRYPT_CIPHERS`' list - NULL suites included by default - and no
/// message. The connection-level `SSL_set_cipher_list` said nothing at
/// all. No pytest passes a cipher string, and a message on stderr is
/// not something the in-process tests can read, which is why the
/// report is now a value as well as a line.
#[test]
fn a_cipher_string_is_reported_without_verbose() {
    let pki = pki();
    let context = context(&pki);
    let mut locked = context.lock().unwrap();
    assert!(!locked.settings.verbose);

    let message = report_cipher_string(&mut locked, "ECDHE-RSA-AES256-GCM-SHA384",
                                       "SSL_CTX_set_cipher_list");
    let message = message.expect("a cipher string went unreported");
    assert!(message.contains("ECDHE-RSA-AES256-GCM-SHA384"), "{}", message);
    assert!(message.contains("ALLCRYPT_CIPHERS"), "{}", message);
    assert_eq!(locked.cipher_strings, vec!["ECDHE-RSA-AES256-GCM-SHA384"]);

    // The default string asks for nothing and says nothing.
    assert_eq!(report_cipher_string(&mut locked, "DEFAULT", "SSL_CTX_set_cipher_list"),
               None);
    assert_eq!(locked.cipher_strings.len(), 1);
    drop(locked);

    // And the connection-level spelling reaches the same context.
    unsafe {
        let ctx = SSL_CTX_new(TLS_client_method());
        let ssl = SSL_new(ctx);
        assert_eq!(SSL_set_cipher_list(ssl, c"AES128-SHA".as_ptr()), 1);
        assert_eq!(ctx_of(ctx).unwrap().inner.lock().unwrap().cipher_strings,
                   vec!["AES128-SHA"]);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
}

// --------------------------------------------------------------- handles ---

/// `SSL_CTX_up_ref` makes the same pointer survive one more
/// `SSL_CTX_free`, and the object is dropped on the last one.
///
/// What was wrong: `SSL_CTX_up_ref` allocated a *second* box sharing
/// the context's `Arc` and leaked it, while `SSL_CTX_free`
/// unconditionally dropped whatever box it was handed. The program
/// holds one pointer and, as the contract says, frees it twice: the
/// first free dropped the box and the second was a double free, with
/// any use in between reading freed memory. Nothing noticed because
/// `curl` and `wget` free each context once in the runs
/// `pytests/test_shim.py` makes, and the leaked clone kept the `Arc`
/// count high enough that nothing else looked wrong.
#[test]
fn up_ref_makes_the_same_context_pointer_survive_one_more_free() {
    unsafe {
        let ctx = SSL_CTX_new(TLS_client_method());
        assert!(!ctx.is_null());
        let shared = Arc::clone(&ctx_of(ctx).unwrap().inner);
        // The handle's reference and this test's.
        assert_eq!(Arc::strong_count(&shared), 2);

        assert_eq!(SSL_CTX_up_ref(ctx), 1);
        assert_eq!(Arc::strong_count(&shared), 2,
                   "SSL_CTX_up_ref allocated a second handle instead of counting");

        SSL_CTX_free(ctx);
        assert_eq!(Arc::strong_count(&shared), 2,
                   "the first free dropped a context with a reference outstanding");
        // The pointer is still the program's to use.
        assert_eq!(SSL_CTX_get_verify_mode(ctx), 0);

        SSL_CTX_free(ctx);
        assert_eq!(Arc::strong_count(&shared), 1,
                   "the last free did not drop the context");
    }
}

/// The same for `SSL_up_ref`, which counted nothing at all.
#[test]
fn up_ref_makes_the_same_connection_pointer_survive_one_more_free() {
    unsafe {
        let ctx = SSL_CTX_new(TLS_client_method());
        let shared = Arc::clone(&ctx_of(ctx).unwrap().inner);
        let ssl = SSL_new(ctx);
        assert!(!ssl.is_null());
        // The context handle, the connection, and this test.
        assert_eq!(Arc::strong_count(&shared), 3);

        assert_eq!(SSL_up_ref(ssl), 1);
        SSL_free(ssl);
        assert_eq!(Arc::strong_count(&shared), 3,
                   "the first free dropped a connection with a reference outstanding");
        assert_eq!(SSL_get_fd(ssl), -1);

        SSL_free(ssl);
        assert_eq!(Arc::strong_count(&shared), 2,
                   "the last free did not drop the connection");
        SSL_CTX_free(ctx);
        assert_eq!(Arc::strong_count(&shared), 1);

        // Null is a no-op for both, as it is in OpenSSL.
        SSL_free(std::ptr::null_mut());
        SSL_CTX_free(std::ptr::null_mut());
    }
}

// -------------------------------------------------------------- SSL_read ---

/// A record the record layer refuses is `SSL_ERROR_SSL`, not a clean
/// end of stream.
///
/// What was wrong: an `Err` from `process` was answered with `0` and
/// `SSL_ERROR_ZERO_RETURN`, on the belief that it might be a
/// close_notify. It never is - the record layer answers `Ok` to a
/// close_notify and moves to `Closed` - so a bad MAC, an unparseable
/// record and a fatal alert from the peer were all reported as the peer
/// finishing cleanly, and a program read a truncated response as a
/// complete one. The origin in `pytests/test_shim.py` never corrupts a
/// record, so the branch was never taken there.
#[test]
fn a_corrupted_record_is_an_error_not_a_clean_close() {
    let pki = pki();
    let mut server = new_server(&pki);
    let context = context(&pki);
    let mut inner = connection(&context);
    connect(&mut inner, &mut server);

    server.write(b"a response the network damaged").unwrap();
    let mut record = server.take_outgoing();
    let last = record.len() - 1;
    record[last] ^= 0x01;
    script(&mut inner).incoming.push_back(record);

    let (result, _) = read(&mut inner, 64);
    assert_eq!(result, -1, "a damaged record was handed over as data");
    assert_eq!(inner.last_error, SSL_ERROR_SSL);
    assert!(inner.failure.is_some());
    // The fatal alert the record layer queued went out.
    assert!(!script(&mut inner).written.is_empty(),
            "no alert was sent for the damaged record");

    // And the connection stays failed: the next read is not a fresh
    // start on whatever bytes follow.
    script(&mut inner).incoming.push_back(vec![0x17, 0x03, 0x03, 0x00, 0x01, 0]);
    let (again, _) = read(&mut inner, 64);
    assert_eq!(again, -1);
    assert_eq!(inner.last_error, SSL_ERROR_SSL);
}

/// A transport that ends without a close_notify is a truncation, and is
/// reported as one - unless the program said to ignore that.
///
/// What was wrong: a bare end of stream was `SSL_ERROR_ZERO_RETURN`,
/// so anything that cut the connection short - a middlebox, a crashed
/// origin, somebody who wanted the page to end early - looked to the
/// program like the peer finishing. OpenSSL 3 reports it as
/// `SSL_ERROR_SSL` ("unexpected eof while reading") for exactly that
/// reason, and only `SSL_OP_IGNORE_UNEXPECTED_EOF` turns it back into a
/// clean end. The pytest origin always closes after a `Content-Length`
/// body the tools stop reading at, so the end of stream was never read.
#[test]
fn an_end_of_stream_without_close_notify_is_an_error() {
    let pki = pki();
    let mut server = new_server(&pki);
    let context = context(&pki);
    let mut inner = connection(&context);
    connect(&mut inner, &mut server);

    script(&mut inner).closed = true;
    let (result, _) = read(&mut inner, 64);
    assert_eq!(result, -1, "a bare end of stream was reported as clean");
    assert_eq!(inner.last_error, SSL_ERROR_SSL);
    assert!(inner.failure.is_some());

    // The same, with the option: the program asked for the bare end to
    // count as clean, as a pre-3.0 OpenSSL would have reported it.
    let mut server = new_server(&pki);
    let mut inner = connection(&context);
    inner.options |= SSL_OP_IGNORE_UNEXPECTED_EOF;
    connect(&mut inner, &mut server);
    script(&mut inner).closed = true;
    let (result, _) = read(&mut inner, 64);
    assert_eq!(result, 0);
    assert_eq!(inner.last_error, SSL_ERROR_ZERO_RETURN);
    assert!(inner.peer_closed);
}

/// A close_notify ends the stream even when the transport stays open,
/// and the data before it is still delivered.
///
/// What was wrong: `peer_closed` was set only when the transport ended,
/// so a server that sent close_notify and kept the socket open - which
/// a server is entitled to do - left `SSL_read` waiting on the socket
/// for an end that the TLS layer had already announced; on a blocking
/// descriptor that is forever. The pytest origin closes the socket
/// right after, so the two ends arrived together there.
#[test]
fn a_close_notify_ends_the_stream_before_the_transport_does() {
    let pki = pki();
    let mut server = new_server(&pki);
    let context = context(&pki);
    let mut inner = connection(&context);
    connect(&mut inner, &mut server);

    server.write(b"the last of it").unwrap();
    server.close().unwrap();
    exchange(&mut inner, &mut server);

    let (result, data) = read(&mut inner, 64);
    assert_eq!(result, 14);
    assert_eq!(data, b"the last of it");
    assert!(inner.peer_closed, "the close_notify was not noticed");

    // The transport is still open - the script is not closed - and the
    // next read must not wait on it.
    let (result, _) = read(&mut inner, 64);
    assert_eq!(result, 0, "the read waited on the transport after close_notify");
    assert_eq!(inner.last_error, SSL_ERROR_ZERO_RETURN);
}

// ------------------------------------------------------------- SSL_write ---

/// A retry after `SSL_ERROR_WANT_WRITE` completes the blocked write
/// rather than starting a second one.
///
/// What was wrong: `SSL_write` encrypted its argument on every call,
/// so when the transport blocked and the program retried with the same
/// buffer - which is OpenSSL's contract for WANT_WRITE - the plaintext
/// was queued a second time behind the remainder of the first, and the
/// peer received it twice. Nothing noticed because every write in
/// `pytests/test_shim.py` is a request of a few hundred bytes over
/// loopback, which the kernel accepts whole; a transport that takes
/// part of a record and then refuses had never been produced.
#[test]
fn a_write_retried_after_want_write_is_not_encrypted_twice() {
    let pki = pki();
    let mut server = new_server(&pki);
    let context = context(&pki);
    let mut inner = connection(&context);
    connect(&mut inner, &mut server);

    // Three records' worth, of which the transport takes one hundred
    // bytes and then blocks.
    let payload = vec![0x5a; 40_000];
    script(&mut inner).capacity = Some(100);
    assert_eq!(write_payload(&mut inner, &payload), -1);
    assert_eq!(inner.last_error, SSL_ERROR_WANT_WRITE);
    assert_eq!(inner.pending_write, Some(payload.len()));
    let queued = inner.outbox.len();
    assert!(queued > 0, "the blocked write left nothing in the outbox");

    // The program retries with the same buffer while the transport is
    // still blocked. The outbox must not grow: growing is the second
    // encryption.
    assert_eq!(write_payload(&mut inner, &payload), -1);
    assert_eq!(inner.last_error, SSL_ERROR_WANT_WRITE);
    assert_eq!(inner.outbox.len(), queued,
               "the retry encrypted the plaintext a second time");

    // The transport drains, and the retry reports the whole write.
    script(&mut inner).capacity = None;
    assert_eq!(write_payload(&mut inner, &payload), payload.len() as c_int);
    assert_eq!(inner.last_error, SSL_ERROR_NONE);
    assert_eq!(inner.pending_write, None);
    assert!(inner.outbox.is_empty());

    // A write after that is a fresh one, so the peer sees the blocked
    // payload exactly once and the next one after it.
    assert_eq!(write_payload(&mut inner, b"after"), 5);
    exchange(&mut inner, &mut server);
    let mut expected = payload.clone();
    expected.extend_from_slice(b"after");
    let received = server.take_incoming();
    assert_eq!(received.len(), expected.len(),
               "the server received {} bytes for {} written",
               received.len(), expected.len());
    assert_eq!(received, expected);
}

/// A retry that offers fewer bytes than the write it completes is
/// refused rather than answered with a length past the caller's buffer.
#[test]
fn a_retry_shorter_than_the_blocked_write_is_refused() {
    let pki = pki();
    let mut server = new_server(&pki);
    let context = context(&pki);
    let mut inner = connection(&context);
    connect(&mut inner, &mut server);

    script(&mut inner).capacity = Some(0);
    assert_eq!(write_payload(&mut inner, b"twelve bytes"), -1);
    assert_eq!(inner.last_error, SSL_ERROR_WANT_WRITE);

    script(&mut inner).capacity = None;
    assert_eq!(write_payload(&mut inner, b"six by"), -1);
    assert_eq!(inner.last_error, SSL_ERROR_SSL);
}
