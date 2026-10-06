"""Prove the SSLContext seam works with the Python ecosystem.

The whole point of these tests is that they do not care what is behind the
seam. They run a real TLS server on loopback with a generated self-signed
certificate, and drive it through `allcrypt_ssl.SSLContext` using the three
integration paths that matter:

  * http.client        - the socket path, what requests/urllib3 sit on
  * urllib3            - the real thing, since it is what requests uses
  * asyncio            - the memory BIO path, the one that needs wrap_bio

When the allcrypt TLS core replaces the stdlib backend these tests should
pass unchanged. That is the test: if they need editing, the seam moved.

No network access is needed or used - everything is loopback.
"""

import asyncio
import datetime
import http.client
import socket
import ssl
import threading

import pytest

import allcrypt_ssl

cryptography = pytest.importorskip("cryptography")
from cryptography import x509                                    # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa        # noqa: E402
from cryptography.x509.oid import NameOID                        # noqa: E402

HOSTNAME = "allcrypt.test"


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    """A self-signed certificate for HOSTNAME, valid now."""
    tmp = tmp_path_factory.mktemp("certs")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOSTNAME)]),
                       critical=False)
        .sign(key, hashes.SHA256())
    )
    certfile = tmp / "cert.pem"
    keyfile = tmp / "key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return str(certfile), str(keyfile)


class TlsEchoServer:
    """A minimal HTTPS server on loopback: one canned response per request."""

    BODY = b"hello from the seam"

    def __init__(self, certfile, keyfile, groups=None):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(certfile, keyfile)
        if groups:
            # Pins the group, so a test can assert which one was
            # negotiated instead of whichever this OpenSSL prefers.
            self.ctx.set_ecdh_curve(groups)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        #: The server's own `tls-unique` for each connection it served,
        #: in order. The only way to check a channel binding is against
        #: what the *other* end computed, and this server is OpenSSL.
        self.bindings = []
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        try:
            socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
        except OSError:
            pass
        self.sock.close()

    def _serve(self):
        while not self.stop.is_set():
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw):
        try:
            with self.ctx.wrap_socket(raw, server_side=True) as conn:
                self.bindings.append(conn.get_channel_binding("tls-unique"))
                conn.recv(65536)
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: %d\r\n"
                    b"Connection: close\r\n\r\n%s" % (len(self.BODY), self.BODY)
                )
        except OSError:
            pass


@pytest.fixture
def server(certs):
    with TlsEchoServer(*certs) as s:
        yield s


def client_context(certfile):
    """A verifying client context built through the seam, not through ssl."""
    ctx = allcrypt_ssl.SSLContext(allcrypt_ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=certfile)
    ctx.check_hostname = True
    ctx.verify_mode = allcrypt_ssl.CERT_REQUIRED
    return ctx


# ------------------------------------------------------------ the three paths --

def test_http_client_through_the_seam(server, certs):
    """http.client accepts any object with wrap_socket. This is the path
    requests and urllib3 ultimately sit on."""
    conn = http.client.HTTPSConnection(
        HOSTNAME, server.port, context=client_context(certs[0]))
    # Point the hostname at loopback without losing it for verification.
    conn.sock = None
    real_create = socket.create_connection
    conn._create_connection = lambda addr, *a, **k: real_create(("127.0.0.1", addr[1]), *a, **k)
    conn.request("GET", "/")
    response = conn.getresponse()
    assert response.status == 200
    assert response.read() == TlsEchoServer.BODY
    conn.close()


def test_urllib3_through_the_seam(server, certs):
    """urllib3 takes ssl_context= directly, which is how requests is configured."""
    urllib3 = pytest.importorskip("urllib3")
    pool = urllib3.HTTPSConnectionPool(
        HOSTNAME, server.port,
        ssl_context=client_context(certs[0]),
        assert_hostname=HOSTNAME,
        retries=False,
    )
    # Resolve the test hostname to loopback for the duration.
    real_create = urllib3.util.connection.create_connection
    urllib3.util.connection.create_connection = (
        lambda addr, *a, **k: real_create(("127.0.0.1", addr[1]), *a, **k))
    try:
        r = pool.request("GET", "/")
        assert r.status == 200
        assert r.data == TlsEchoServer.BODY
    finally:
        urllib3.util.connection.create_connection = real_create
        pool.close()


def test_asyncio_through_the_seam(server, certs):
    """asyncio drives wrap_bio, not wrap_socket. This is the memory BIO path
    the sans-I/O core will plug straight into."""
    async def fetch():
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", server.port,
            ssl=client_context(certs[0]), server_hostname=HOSTNAME)
        writer.write(b"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                     % HOSTNAME.encode())
        await writer.drain()
        data = await reader.read()
        writer.close()
        return data

    data = asyncio.run(fetch())
    assert b"200 OK" in data
    assert TlsEchoServer.BODY in data


# --------------------------------------------------------------- the contract --

def test_verification_actually_rejects(server):
    """The failure that matters: an SSLContext shim where verify_mode
    silently does nothing looks identical to a working one until it doesn't.
    Connect without trusting the certificate and require a rejection."""
    ctx = allcrypt_ssl.create_default_context()
    with pytest.raises(allcrypt_ssl.SSLError):
        with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=HOSTNAME):
                pass


def test_hostname_mismatch_rejected(server, certs):
    """Right CA, wrong name, must still fail."""
    ctx = client_context(certs[0])
    with pytest.raises(allcrypt_ssl.SSLCertVerificationError):
        with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="not-the-right-name.test"):
                pass


def test_defaults_are_safe():
    """create_default_context must verify, like the standard library's."""
    ctx = allcrypt_ssl.create_default_context()
    assert ctx.check_hostname is True
    assert ctx.verify_mode == allcrypt_ssl.CERT_REQUIRED


def test_wrap_bio_is_usable_directly(server, certs):
    """The memory BIO path on its own, without asyncio in the way - this is
    the shape the sans-I/O core has to satisfy: feed it bytes, take bytes."""
    ctx = client_context(certs[0])
    incoming, outgoing = allcrypt_ssl.MemoryBIO(), allcrypt_ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=HOSTNAME)

    with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw:
        # Drive the handshake by hand, moving bytes between BIO and socket.
        while True:
            try:
                obj.do_handshake()
                break
            except allcrypt_ssl.SSLWantReadError:
                to_send = outgoing.read()
                if to_send:
                    raw.sendall(to_send)
                received = raw.recv(65536)
                if not received:
                    raise AssertionError("server closed during handshake")
                incoming.write(received)
        pending = outgoing.read()
        if pending:
            raw.sendall(pending)

        assert obj.version() is not None
        assert obj.cipher() is not None


def test_backend_is_declared():
    """Tests assert on the backend so the swap is visible rather than silent.

    This assertion said ``stdlib`` from the first version until the TLS core
    landed, and it was written to fail on the day it stopped being true. It
    is now the other way round, and it fails again if the backend ever
    regresses.
    """
    assert allcrypt_ssl.BACKEND == "allcrypt"
    assert "backend=allcrypt" in repr(allcrypt_ssl.create_default_context())


def test_the_seam_tests_actually_used_our_stack(certs):
    """The one that stops this whole file from passing vacuously.

    Every test above drives a real server through `allcrypt_ssl` and asserts
    on the bytes that come back - which a transparent fallback to the
    standard library would satisfy just as well. For a while it did exactly
    that: seven of these eight tests passed without executing a line of
    allcrypt. So the backend is asserted on both ends, the context that
    made the connection and the connection itself, because only the second
    one survives being handed to `http.client`.
    """
    certfile, _ = certs
    with TlsEchoServer(*certs) as server:
        ctx = allcrypt_ssl.create_default_context(cafile=certfile)
        raw = socket.create_connection(("127.0.0.1", server.port))
        with ctx.wrap_socket(raw, server_hostname=HOSTNAME) as sock:
            assert ctx.backend_in_use == "allcrypt"
            assert getattr(sock, "backend_in_use", "stdlib") == "allcrypt"
            # And it really did negotiate, rather than reporting a backend
            # it never used.
            #
            # **1.3, because the shim's ceiling is 1.3.** This said 1.2
            # while the shim stopped there, and the number is worth
            # pinning rather than accepting whatever comes back: a
            # default that quietly drops to a lower version is exactly
            # the failure a shim is most likely to have and least likely
            # to notice.
            assert sock.version() == "TLSv1.3"
            name, version, bits = sock.cipher()
            assert version == "TLSv1.3"
            assert bits >= 128, name

        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_hostname=HOSTNAME)
        assert ctx.backend_in_use == "allcrypt"
        assert getattr(obj, "backend_in_use", "stdlib") == "allcrypt"


# -------------------------------------------------------- the suite list ---
#
# `get_ciphers` is how a caller finds out what asking for "modern" or
# "legacy" actually got them, and it is what check_live.py uses to report
# the suites nothing in its matrix can reach. That report must be derived
# rather than typed, or it goes stale the moment a suite is added.

def test_get_ciphers_reports_what_the_selection_offers():
    import allcrypt
    import allcrypt_ssl

    context = allcrypt_ssl.create_default_context()
    modern = [entry["name"] for entry in context.get_ciphers()]
    assert modern, "the default selection offers nothing"
    assert modern == allcrypt.tls_suite_names("modern")

    # Every name must be one the registry knows. A selection that
    # reported a suite nobody has would be worse than reporting none.
    known = set(allcrypt.tls_suites_available)
    assert set(modern) <= known

    context.set_ciphers("legacy")
    legacy = [entry["name"] for entry in context.get_ciphers()]
    assert set(modern) < set(legacy), \
        "legacy must be strictly wider than modern"

    # The broken suites are in legacy and not in modern, which is the
    # whole reason the two exist.
    assert any("3DES" in name or "RC4" in name for name in legacy)
    assert not any("3DES" in name or "RC4" in name for name in modern)


def test_get_ciphers_follows_a_named_list():
    import allcrypt_ssl

    context = allcrypt_ssl.create_default_context()
    context.set_ciphers("AES128-SHA,RC4-SHA")
    names = [entry["name"] for entry in context.get_ciphers()]
    assert names == ["TLS_RSA_WITH_AES_128_CBC_SHA",
                     "TLS_RSA_WITH_RC4_128_SHA"]


def test_an_unknown_suite_name_raises_rather_than_returning_nothing():
    import allcrypt

    # An empty list would read as "this selection offers nothing", and a
    # typo would read as neither - so it has to be an error.
    with pytest.raises(Exception):
        allcrypt.tls_suite_names("NOT-A-SUITE")


def test_the_gost_suites_are_offered_by_default():
    """All three RFC 9189 suites are implemented, so all three are offered.

    Offering a suite we cannot finish is a handshake that fails after
    the server has already committed to it, so the list and the
    implementation have to agree - which is what this asserts, rather
    than that any particular one is present.
    """
    import allcrypt

    gost = [name for name in allcrypt.tls_suites_available
            if "GOSTR341112" in name]

    # **Two families under one prefix**, and they share nothing but the
    # name. RFC 9189's are TLS 1.2 with a GOST key exchange; RFC 9367's
    # are TLS 1.3, where the suite names an AEAD and a hash and no key
    # exchange at all. Counted apart so that adding one family cannot
    # make up for losing the other.
    mgm = [name for name in gost if "_MGM_" in name]
    older = [name for name in gost if name not in mgm]

    # Three suites and four names in the older family: CNT_IMIT is
    # offered at both of its code points, the one IANA assigned and the
    # private-use one it had before - RFC 9189 section 10. Which of the
    # two a box understands is exactly what cannot be known before the
    # handshake.
    assert len(older) == 4, older
    assert sum(1 for name in older if name.endswith("_LEGACY")) == 1, older

    # RFC 9367's four: two ciphers times two re-keying schedules. The
    # `_L` and `_S` forms differ only in constants, so a list with three
    # of them is the shape to catch here.
    assert len(mgm) == 4, mgm
    assert sum(1 for name in mgm if name.endswith("_L")) == 2, mgm
    assert sum(1 for name in mgm if name.endswith("_S")) == 2, mgm

    for selection in ("modern", "legacy", "all"):
        names = set(allcrypt.tls_suite_names(selection))
        assert set(gost) <= names, sorted(set(gost) - names)


# ----------------------------------------------------------- TLS 1.3 things ---
#
# The shim covered SSLv3 to TLS 1.2 for a long time, not because the
# library stopped there - its own client already spoke 1.3 - but because
# raising the ceiling means deciding what `session`, `session_reused` and
# ALPN do. These are that decision, asserted.


class Tls13Server(TlsEchoServer):
    """The same server, pinned to TLS 1.3 and willing to negotiate ALPN."""

    def __init__(self, certfile, keyfile, alpn=None):
        super().__init__(certfile, keyfile)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        if alpn:
            self.ctx.set_alpn_protocols(alpn)
        self.selected = []

    def _handle(self, raw):
        try:
            with self.ctx.wrap_socket(raw, server_side=True) as conn:
                self.selected.append(conn.selected_alpn_protocol())
                # The server's own channel binding. Appended in
                # connection order, which holds because every test using
                # it completes one round trip before starting the next.
                self.bindings.append(conn.get_channel_binding("tls-unique"))
                conn.recv(65536)
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: %d\r\n"
                    b"Connection: close\r\n\r\n%s" % (len(self.BODY), self.BODY)
                )
        except OSError:
            pass


def _round_trip(context, port, session=None):
    """One connection through the shim, read to the end.

    Read to the end on purpose: a TLS 1.3 NewSessionTicket arrives under
    the application keys, so a connection that hangs up after the
    handshake has no session worth handing on - and the next one would
    silently do a full handshake while the test believed it was testing
    resumption.
    """
    raw = socket.create_connection(("127.0.0.1", port))
    sock = context.wrap_socket(raw, server_hostname=HOSTNAME, session=session)
    try:
        sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        body = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
        return sock, body
    finally:
        sock.close()


def test_the_shim_speaks_tls13(certs):
    """Against a server that will speak nothing else.

    Which is the assertion: a shim that had quietly fallen back to the
    standard library would also succeed here, so the backend is checked
    on the connection as well as on the context.
    """
    certfile, keyfile = certs
    with Tls13Server(certfile, keyfile) as server:
        context = client_context(certfile)
        sock, body = _round_trip(context, server.port)
        assert context.backend_in_use == "allcrypt"
        assert getattr(sock, "backend_in_use", "stdlib") == "allcrypt"
        assert sock.version() == "TLSv1.3"
        assert TlsEchoServer.BODY in body


def test_a_session_resumes_the_next_connection(certs):
    """`session` out of one connection, `session=` into the next.

    **`session_reused` is OpenSSL's word, not ours**: the server opened a
    ticket it issued, derived the binder key from the PSK inside it, and
    recomputed the binder over a transcript it built independently. A
    round trip against our own server would prove only that we can read
    our own writing.
    """
    certfile, keyfile = certs
    with Tls13Server(certfile, keyfile) as server:
        context = client_context(certfile)
        first, _ = _round_trip(context, server.port)
        assert not first.session_reused, "the first connection cannot resume"
        session = first.session
        assert session.has_ticket, "no ticket arrived to resume with"

        second, body = _round_trip(context, server.port, session=session)
        assert second.session_reused, "the ticket was not accepted"
        assert TlsEchoServer.BODY in body
        # A resumed 1.3 connection sends no certificate - the PSK is what
        # authenticates - so this being empty is normal and is the thing
        # a caller has to know before reading it as a failure.
        assert second.getpeercert(True) is None


def test_a_session_offers_each_ticket_once(certs):
    """Offering one twice lets a passive observer link the connections,
    which is what a ticket's obfuscated age exists to prevent. So
    resumption takes a ticket out of the session rather than copying it,
    and a session handed to more connections than it has tickets simply
    runs out."""
    certfile, keyfile = certs
    with Tls13Server(certfile, keyfile) as server:
        context = client_context(certfile)
        first, _ = _round_trip(context, server.port)
        session = first.session
        assert len(session) >= 1
        # **The identity of the ticket, not the count.** A resumed
        # connection is issued new tickets and puts them into the same
        # session, so the count comes straight back up - a test watching
        # the number would pass with a session that offered the same
        # ticket every time.
        offered = session._tickets[0]

        second, _ = _round_trip(context, server.port, session=session)
        assert second.session_reused
        assert offered not in session._tickets, "the ticket was offered twice"


def test_a_session_held_from_before_the_tickets_fills_in(certs):
    """The session object is the connection's own, not a snapshot.

    A TLS 1.3 NewSessionTicket arrives under the application keys, so a
    caller that reads `.session` as soon as the handshake finishes gets
    an object with nothing in it yet. It has to be the *same* object the
    tickets land in afterwards, or that caller holds an empty session
    forever and resumption silently never happens.

    This is what makes the collection on every read load-bearing rather
    than redundant with the `session` property, which only collects when
    it is asked.
    """
    certfile, keyfile = certs
    with Tls13Server(certfile, keyfile) as server:
        context = client_context(certfile)
        raw = socket.create_connection(("127.0.0.1", server.port))
        sock = context.wrap_socket(raw, server_hostname=HOSTNAME)
        try:
            early = sock.session            # before any application data
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
            while sock.recv(65536):
                pass
        finally:
            sock.close()
        assert early.has_ticket, "the held session never filled in"

        second, _ = _round_trip(context, server.port, session=early)
        assert second.session_reused


def test_alpn_through_the_shim(certs):
    """`set_alpn_protocols` reaches our stack rather than only the
    fallback context - which it did not, while ALPN was unimplemented and
    `selected_alpn_protocol` returned `None` unconditionally."""
    certfile, keyfile = certs
    with Tls13Server(certfile, keyfile, alpn=["h2", "http/1.1"]) as server:
        context = client_context(certfile)
        context.set_alpn_protocols(["http/1.1", "h2"])
        sock, _ = _round_trip(context, server.port)
        assert getattr(sock, "backend_in_use", "stdlib") == "allcrypt"
        # The server's preference wins, and the two lists are in
        # opposite orders so that this says something.
        assert sock.selected_alpn_protocol() == "h2"
        assert server.selected == ["h2"]


def test_an_openssl_session_is_refused(certs):
    """An `ssl.SSLSession` is OpenSSL's own connection state and there is
    nothing here that can read one. Refusing it by type is better than
    ignoring it: a caller that passed one would otherwise get a full
    handshake and believe it had resumed."""
    certfile, keyfile = certs
    with Tls13Server(certfile, keyfile) as server:
        plain = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        plain.load_verify_locations(cafile=certfile)
        raw = socket.create_connection(("127.0.0.1", server.port))
        with plain.wrap_socket(raw, server_hostname=HOSTNAME) as native:
            native.sendall(b"GET / HTTP/1.0\r\n\r\n")
            native.recv(65536)
            theirs = native.session

        context = client_context(certfile)
        raw = socket.create_connection(("127.0.0.1", server.port))
        with pytest.raises(TypeError):
            context.wrap_socket(raw, server_hostname=HOSTNAME, session=theirs)
        raw.close()


# ------------------------------------------------------------ the server side ---
#
# The shim fell back to the standard library on the accepting side for a
# reason that was never about TLS: `load_cert_chain` reads a private key
# out of a PEM file, and this library had no private-key parser. With one,
# `wrap_socket(server_side=True)` is ours.


def server_context(certfile, keyfile, **fields):
    context = allcrypt_ssl.SSLContext(allcrypt_ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    for name, value in fields.items():
        setattr(context, name, value)
    return context


class OurEchoServer:
    """The seam's own server, serving one connection per accept."""

    BODY = b"served by allcrypt"

    def __init__(self, context):
        self.context = context
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.seen = []
        self.errors = []
        self.stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def _serve(self):
        while not self.stop.is_set():
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(raw,),
                             daemon=True).start()

    def _handle(self, raw):
        try:
            conn = self.context.wrap_socket(raw, server_side=True)
            self.seen.append({
                "backend": getattr(conn, "backend_in_use", "stdlib"),
                "version": conn.version(),
                "sni": conn.server_hostname,
                "alpn": conn.selected_alpn_protocol(),
            })
            conn.recv(65536)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                         b"Connection: close\r\n\r\n%s"
                         % (len(self.BODY), self.BODY))
            conn.close()
        except Exception as reason:                       # noqa: BLE001
            self.errors.append(reason)
        finally:
            try:
                raw.close()
            except OSError:
                pass


def _fetch(port, certfile, alpn=None, version=None):
    """An OpenSSL client against our server, read to the end.

    Returns what it *saw*, not the socket, and reads it **before** the
    body: `ssl.SSLSocket.version()` answers `None` once the peer's
    close_notify has been processed, so a test asking afterwards would
    be asserting on the shutdown rather than on the handshake.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=certfile)
    if alpn:
        context.set_alpn_protocols(alpn)
    if version:
        context.minimum_version = version
        context.maximum_version = version
    raw = socket.create_connection(("127.0.0.1", port))
    with context.wrap_socket(raw, server_hostname=HOSTNAME) as sock:
        saw = {"version": sock.version(),
               "alpn": sock.selected_alpn_protocol()}
        sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        body = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
        return saw, body


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_2,
                                     ssl.TLSVersion.TLSv1_3])
def test_the_shim_serves_through_our_stack(certs, version):
    """An OpenSSL client, our server, both versions.

    The backend is asserted on the *connection*, because a shim that
    fell back would serve this perfectly and the test would pass having
    executed none of our code. That has happened here before: seven of
    the eight original seam tests did exactly that.
    """
    certfile, keyfile = certs
    with OurEchoServer(server_context(certfile, keyfile)) as server:
        saw, body = _fetch(server.port, certfile, version=version)
        assert not server.errors, server.errors
        assert OurEchoServer.BODY in body
        assert server.seen[-1]["backend"] == "allcrypt"
        assert server.seen[-1]["version"] == saw["version"]
        assert server.seen[-1]["sni"] == HOSTNAME


def test_the_server_side_negotiates_alpn(certs):
    certfile, keyfile = certs
    context = server_context(certfile, keyfile)
    context.set_alpn_protocols(["h2", "http/1.1"])
    with OurEchoServer(context) as server:
        # Opposite orders, so this says the *server's* preference won.
        saw, _ = _fetch(server.port, certfile, alpn=["http/1.1", "h2"])
        assert saw["alpn"] == "h2"
        assert server.seen[-1]["alpn"] == "h2"
        assert server.seen[-1]["backend"] == "allcrypt"


def test_a_key_we_cannot_read_falls_back_rather_than_failing(certs, tmp_path):
    """A key this library genuinely cannot read still falls back.

    **An encrypted key is no longer one of them**, which is what this
    test used to assert: PBES1, PBES2 and the PKCS#12 schemes landed and
    `load_cert_chain` now honours `password=`, so the encrypted case is
    covered by `test_an_encrypted_key_is_served_by_us_now` below. The
    fallback still has to work, though, for a key on a curve this
    library does not implement or in a format nothing here parses - so
    the case is kept and the input changed to one that is really
    unreadable.

    A shim that refused to serve would break a context the standard
    library handles perfectly; it falls back, and says so, because a
    silent fallback is the thing this module exists not to do.
    """
    from cryptography.hazmat.primitives.asymmetric import ec as pyec
    certfile, _ = certs
    key = pyec.generate_private_key(pyec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(2)
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=1))
                   .add_extension(
                       x509.SubjectAlternativeName([x509.DNSName(HOSTNAME)]),
                       critical=False)
                   .sign(key, hashes.SHA256()))
    locked_cert = tmp_path / "locked.pem"
    locked_key = tmp_path / "locked.key"
    locked_cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    locked_key.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"hunter2")))

    context = allcrypt_ssl.SSLContext(allcrypt_ssl.PROTOCOL_TLS_SERVER)
    # The wrong password is a key we cannot read, and the one shape of
    # "unreadable" that is easy to produce on purpose. The standard
    # library is given the right one, so it can still serve.
    context.load_cert_chain(str(locked_cert), str(locked_key), "hunter2")
    assert context._identity is not None, (
        "an encrypted key with the right password is readable now")

    # Now a key that is genuinely unreadable *here* and perfectly
    # readable by OpenSSL: brainpoolP256r1, which this library does not
    # implement. (This was P-521, until P-521 arrived.)
    # That is the shape the fallback exists for - not a corrupt file,
    # which both sides would refuse, but a real key whose curve we do
    # not compute.
    far_key = pyec.generate_private_key(pyec.BrainpoolP256R1())
    far_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME)])
    far_cert = (x509.CertificateBuilder()
                .subject_name(far_name).issuer_name(far_name)
                .public_key(far_key.public_key()).serial_number(4)
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(HOSTNAME)]),
                    critical=False)
                .sign(far_key, hashes.SHA256()))
    far_cert_path = tmp_path / "brainpool.pem"
    far_key_path = tmp_path / "brainpool.key"
    far_cert_path.write_bytes(far_cert.public_bytes(serialization.Encoding.PEM))
    far_key_path.write_bytes(far_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))

    fallback = allcrypt_ssl.SSLContext(allcrypt_ssl.PROTOCOL_TLS_SERVER)
    fallback.load_cert_chain(str(far_cert_path), str(far_key_path))
    assert fallback._identity is None
    assert "curve" in fallback._identity_error.lower(), fallback._identity_error
    assert not fallback._can_use_allcrypt(server_side=True)

    with OurEchoServer(context) as server:
        _, body = _fetch(server.port, str(locked_cert))
        assert not server.errors, server.errors
        assert OurEchoServer.BODY in body
        # And with a readable key it is ours, not the fallback.
        assert server.seen[-1]["backend"] == "allcrypt"


@pytest.mark.parametrize("password", [b"hunter2", "hunter2", lambda: b"hunter2"],
                         ids=["bytes", "str", "callable"])
def test_an_encrypted_key_is_served_by_us_now(certs, tmp_path, password):
    """`load_cert_chain(..., password=...)` used to be passed only to the
    standard library, with a comment saying this library could not
    decrypt a private key.

    That was true when it was written and stopped being true when PBES1,
    PBES2 and the PKCS#12 schemes landed - so every context with an
    encrypted key was quietly served by OpenSSL for no reason. A stale
    comment about a fallback is expensive in a way other stale comments
    are not: it reads as a decision, so nobody re-tests it.

    All three shapes the standard library accepts are covered, because a
    callable is how a passphrase gets prompted for rather than held in a
    variable, and a shim taking only `bytes` would quietly force the
    caller to hold it.
    """
    from cryptography.hazmat.primitives.asymmetric import ec as pyec
    key = pyec.generate_private_key(pyec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(3)
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=1))
                   .add_extension(
                       x509.SubjectAlternativeName([x509.DNSName(HOSTNAME)]),
                       critical=False)
                   .sign(key, hashes.SHA256()))
    cert_path = tmp_path / "enc.pem"
    key_path = tmp_path / "enc.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"hunter2")))

    context = allcrypt_ssl.SSLContext(allcrypt_ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path), password)
    assert context._identity is not None
    assert context._identity_error is None
    assert context._can_use_allcrypt(server_side=True)

    with OurEchoServer(context) as server:
        _, body = _fetch(server.port, str(cert_path))
        assert not server.errors, server.errors
        assert OurEchoServer.BODY in body
        assert server.seen[-1]["backend"] == "allcrypt"


def test_a_server_without_a_certificate_falls_back(certs):
    """A context nobody gave a certificate to cannot serve through us,
    and the standard library's error is the better one - it says the
    certificate is missing, where ours would say something about a key
    that was never loaded."""
    context = allcrypt_ssl.SSLContext(allcrypt_ssl.PROTOCOL_TLS_SERVER)
    assert not context._can_use_allcrypt(server_side=True)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_the_server_side_does_not_offer_sslv3(certs):
    """The low floor exists to reach old *servers*.

    Serving SSLv3 to whoever connects is the opposite of that - it is
    putting POODLE in front of them - so a server context asking for it
    falls back rather than being quietly obliged. `allcrypt.TlsServer`
    will still do it directly, where it is a decision somebody made.
    """
    certfile, keyfile = certs
    context = server_context(certfile, keyfile)
    context.minimum_version = allcrypt_ssl.TLSVersion.SSLv3
    assert not context._can_use_allcrypt(server_side=True)


# --------------------------------------------- OP_NO_TICKET, and what it does ---

def test_op_no_ticket_means_no_session_to_resume_with(certs):
    """**The flag urllib3 sets on every context it builds.**

    It used to be stored and forgotten, so a caller that asked for no
    session tickets got them - and nothing anywhere said so. The failure
    is silent in the direction that matters: tickets are key material a
    later connection can be resumed from, and a caller turning them off
    has usually decided that storing any is the problem.

    Both halves are checked, because they are separately breakable: a
    context with the flag must offer none *and* keep none the server
    sent. A TLS 1.3 server issues tickets whether or not anyone wants
    them, so discarding what arrives is as load bearing as not offering.
    """
    certfile, keyfile = certs
    with Tls13Server(certfile, keyfile) as server:
        # Without the flag, resumption works - so the test below is
        # measuring the flag rather than a server that never issued one.
        allowed = client_context(certfile)
        first, _ = _round_trip(allowed, server.port)
        assert first.session.has_ticket, "no ticket arrived to resume with"
        second, _ = _round_trip(allowed, server.port, session=first.session)
        assert second.session_reused

        refused = client_context(certfile)
        refused.options |= allcrypt_ssl.OP_NO_TICKET
        assert refused.option_report()["OP_NO_TICKET"] == "acted on"

        third, _ = _round_trip(refused, server.port)
        assert not third.session.has_ticket, (
            "OP_NO_TICKET was set and the session kept a ticket anyway")

        # And a session from a context that did collect one is not
        # offered by a context that says no - the other half of the flag.
        fourth, _ = _round_trip(refused, server.port, session=first.session)
        assert not fourth.session_reused, (
            "OP_NO_TICKET was set and a stored ticket was offered anyway")


def test_tls_unique_on_a_resumed_connection_is_the_peers_finished(certs):
    """Which Finished is the channel binding depends on resumption.

    For a client the rule is OpenSSL's - our own, unless the session was
    resumed, and then the peer's. On a full handshake at TLS 1.2 the two
    readings coincide, which is why only a *resumed* connection can tell
    them apart, and a client that always used its own would agree with
    itself everywhere and with the server on half of its connections.
    SCRAM then fails looking like a bad password.
    """
    certfile, keyfile = certs
    with Tls13Server(certfile, keyfile) as server:
        context = client_context(certfile)
        first, _ = _round_trip(context, server.port)
        full = first.get_channel_binding("tls-unique")
        assert full is not None
        assert not first.session_reused

        second, _ = _round_trip(context, server.port, session=first.session)
        assert second.session_reused, "nothing was resumed, so nothing is proved"
        resumed = second.get_channel_binding("tls-unique")
        assert resumed is not None

        # Two different connections, so two different bindings - the
        # property the whole mechanism rests on.
        assert resumed != full

        # **And each one matches what the server computed.** This is the
        # assertion that discriminates: on a resumed connection our own
        # Finished is still a perfectly good, perfectly different value,
        # so comparing the two connections to each other passes whichever
        # Finished we picked. Only the peer can say which is right.
        assert len(server.bindings) >= 2, server.bindings
        assert full == server.bindings[0], "the full handshake's binding differs"
        assert resumed == server.bindings[1], (
            "the resumed connection's binding differs from the server's - "
            "the wrong Finished was chosen")


def test_an_unknown_channel_binding_type_says_so_at_the_shim(certs):
    """Refused twice, and the message is pinned to the outer one.

    Removing the shim's check leaves every test passing, because the
    core refuses an unknown type too - defence in depth rather than a
    hole, but a breakage sweep cannot tell those apart. So the wording
    is asserted: the standard library's message is what a caller catches
    and greps for.
    """
    certfile, keyfile = certs
    with Tls13Server(certfile, keyfile) as server:
        context = client_context(certfile)
        sock, _ = _round_trip(context, server.port)
        for unknown in ["tls-server-end-point", "tls-unique-for-telnet", ""]:
            with pytest.raises(ValueError) as caught:
                sock.get_channel_binding(unknown)
            assert "channel binding type not implemented" in str(caught.value), \
                str(caught.value)


@pytest.mark.parametrize("group,expected", [
    ("X25519", "x25519"),
    ("X448", "x448"),
    ("prime256v1", "secp256r1"),
])
def test_named_group_through_the_shim(certs, group, expected):
    """`named_group()` on a real socket, against a server pinned to one
    group.

    The accessor exists because `scripts/check_live.py` wanted this value
    and was reaching into `sock._connection._client` for it. Tested
    through the shim rather than on the core client because the private
    path is exactly what a core-level test would keep working.

    **X448 is the row this was added for** - it is a supported group now,
    and the only way to tell an X448 connection from an X25519 one after
    the fact is to ask. The other two are here so that a stub returning a
    constant fails.
    """
    certfile, keyfile = certs
    with TlsEchoServer(certfile, keyfile, groups=group) as server:
        context = client_context(certfile)
        sock, body = _round_trip(context, server.port)
        try:
            assert sock.named_group() == expected
            assert TlsEchoServer.BODY in body
        finally:
            sock.close()
