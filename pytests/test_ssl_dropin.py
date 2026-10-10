"""`import allcrypt_ssl as ssl` as a drop-in for the standard library.

Three different claims, and they need three different kinds of test.

**The namespace is complete.** Measured against `dir(ssl)` rather than
listed, because a list drifts and the point is that nothing is missing.
`urllib3` alone reads a dozen module attributes at import time, and a
missing one is an `AttributeError` inside somebody else's package.

**The flags mean something.** `OP_*` and `VERIFY_*` are not data: a
caller sets them expecting behaviour. Exposing one that is absorbed and
ignored turns "I asked for no session tickets" into "I got session
tickets", so every flag either changes what this stack does, is already
true of it, or raises - and these tests are what hold that, because a
flag quietly doing nothing looks exactly like a flag working.

**Real code drives it.** `http.client`, `urllib3` and `requests` against
a loopback server, with `sys.modules["ssl"]` replaced - and asserting
`backend_in_use == "allcrypt"` throughout, because a shim that silently
fell back to OpenSSL would pass every other assertion in this file.
"""

import datetime
import socket
import ssl as real_ssl
import subprocess
import sys
import threading
import time

import pytest

import allcrypt_ssl

cryptography = pytest.importorskip("cryptography")
from cryptography import x509                                     # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa         # noqa: E402
from cryptography.x509.oid import NameOID                         # noqa: E402


# ------------------------------------------------------------ the namespace ---

def test_every_name_the_standard_library_exports_is_here():
    """Measured, not listed.

    The count matters less than the principle: code substituting this
    module reaches for names nobody thought about, and each missing one
    surfaces far from here.
    """
    theirs = {n for n in dir(real_ssl) if not n.startswith("_")}
    ours = {n for n in dir(allcrypt_ssl) if not n.startswith("_")}
    missing = sorted(theirs - ours)
    assert not missing, "missing from allcrypt_ssl: {}".format(missing)


def test_the_private_helpers_the_standard_library_modules_call_are_here():
    """`smtplib`, `imaplib`, `poplib` and `ftplib` all call
    `ssl._create_stdlib_context`, and `http.client` reads
    `ssl._create_default_https_context`. Private names, and load
    bearing."""
    assert callable(allcrypt_ssl._create_stdlib_context)
    assert callable(allcrypt_ssl._create_default_https_context)

    # And the stdlib-shaped one does *not* verify by default, which is
    # the standard library's choice: those modules turn verification on
    # themselves when they mean to.
    context = allcrypt_ssl._create_stdlib_context()
    assert context.verify_mode == allcrypt_ssl.CERT_NONE
    assert context.check_hostname is False


def test_the_constants_we_answer_differently_are_deliberate():
    """Most constants are facts about TLS and are re-exported. These are
    the ones where our answer differs, and each would be a lie the other
    way round."""
    # This Python's OpenSSL has no SSLv3 at all; our record layer does.
    assert allcrypt_ssl.HAS_SSLv3 is True
    assert real_ssl.HAS_SSLv3 is False

    # SSLv2 is not "old", it is unauthenticated, and it is not coming.
    assert allcrypt_ssl.HAS_SSLv2 is False

    # NPN was replaced by ALPN and removed; nothing here implements it.
    assert allcrypt_ssl.HAS_NPN is False

    # Python 3.13's external-PSK callbacks have nothing behind them here,
    # so the flag that guards them says so whatever this Python's own
    # OpenSSL can do. Missing, it failed
    # `test_every_name_the_standard_library_exports_is_here` on 3.13 and
    # was invisible on 3.12, which has no such name.
    assert allcrypt_ssl.HAS_PSK is False

    assert allcrypt_ssl.HAS_ALPN is True

    # **Not shaped like an OpenSSL version, on purpose.** urllib3 tests
    # `OPENSSL_VERSION.startswith("OpenSSL ")` before relying on
    # OpenSSL-specific behaviour, so telling the truth is also what makes
    # it stop assuming things about this stack.
    assert not allcrypt_ssl.OPENSSL_VERSION.startswith("OpenSSL ")
    assert allcrypt_ssl.OPENSSL_VERSION.startswith("allcrypt ")
    # requests formats it with `:x`, so it has to be an integer.
    assert isinstance(allcrypt_ssl.OPENSSL_VERSION_NUMBER, int)
    assert "{:x}".format(allcrypt_ssl.OPENSSL_VERSION_NUMBER)


def test_the_conversion_helpers_agree_with_the_standard_library():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "helper.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(1)
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=1))
                   .sign(key, hashes.SHA256()))
    der = certificate.public_bytes(serialization.Encoding.DER)

    assert (allcrypt_ssl.DER_cert_to_PEM_cert(der)
            == real_ssl.DER_cert_to_PEM_cert(der))
    pem = real_ssl.DER_cert_to_PEM_cert(der)
    assert (allcrypt_ssl.PEM_cert_to_DER_cert(pem)
            == real_ssl.PEM_cert_to_DER_cert(pem))
    with pytest.raises(ValueError):
        allcrypt_ssl.PEM_cert_to_DER_cert("no certificate in here")


@pytest.mark.parametrize("stamp", [
    "Jun  1 00:00:00 2024 GMT", "Jan 15 23:59:59 1999 GMT",
    "Jul  4 12:00:00 2030 GMT", "Dec 31 00:00:01 2049 GMT",
    "Feb 29 06:30:00 2024 GMT",
])
def test_cert_time_to_seconds_matches_the_standard_library(stamp):
    """Parsed locale-independently, with the month names spelled out
    rather than taken from `strptime` - the bug the standard library
    fixed in 3.5 and worth not reintroducing."""
    assert (allcrypt_ssl.cert_time_to_seconds(stamp)
            == real_ssl.cert_time_to_seconds(stamp))


def test_cert_time_to_seconds_refuses_junk():
    for bad in ["not a date", "Xyz  1 00:00:00 2024 GMT",
                "Jun  1 00:00:00 2024", ""]:
        with pytest.raises(ValueError):
            allcrypt_ssl.cert_time_to_seconds(bad)


def test_the_random_helpers_come_from_this_library():
    assert len(allcrypt_ssl.RAND_bytes(48)) == 48
    assert allcrypt_ssl.RAND_bytes(32) != allcrypt_ssl.RAND_bytes(32)
    assert allcrypt_ssl.RAND_status() is True
    material, strong = allcrypt_ssl.RAND_pseudo_bytes(16)
    assert len(material) == 16 and strong is True
    # Accepted and discarded: there is no user-space pool to add to.
    allcrypt_ssl.RAND_add(b"entropy", 1.0)


# ------------------------------------------------------- options that act ---

def test_every_option_the_context_holds_is_accounted_for():
    """No fourth answer. A flag that would need one raises when set, so
    `unknown` appearing here is the report and the implementation having
    drifted apart."""
    context = allcrypt_ssl.create_default_context()
    for name, verdict in context.option_report().items():
        assert verdict in ("acted on", "already true", "not applicable"), \
            "{} is {}".format(name, verdict)


def test_the_options_urllib3_sets_are_all_accounted_for():
    """urllib3 sets these on every context it builds. `OP_NO_TICKET` is
    the one that used to be absorbed and ignored, which meant a caller
    asking for no session tickets got them."""
    context = allcrypt_ssl.create_default_context()
    context.options |= (allcrypt_ssl.OP_NO_SSLv2 | allcrypt_ssl.OP_NO_SSLv3
                        | allcrypt_ssl.OP_NO_COMPRESSION
                        | allcrypt_ssl.OP_NO_TICKET)
    report = context.option_report()
    assert report["OP_NO_TICKET"] == "acted on"
    assert report["OP_NO_COMPRESSION"] == "already true"
    assert report["OP_NO_SSLv3"] == "acted on"


def test_op_no_version_narrows_the_offer():
    context = allcrypt_ssl.create_default_context()
    before = context._version_window()
    context.options |= allcrypt_ssl.OP_NO_TLSv1_3
    after = context._version_window()
    assert before[1] == allcrypt_ssl.TLSVersion.TLSv1_3
    assert after[1] == allcrypt_ssl.TLSVersion.TLSv1_2, \
        "OP_NO_TLSv1_3 did not remove 1.3 from the offer"


def test_a_gap_in_the_middle_is_refused_rather_than_approximated():
    """This stack offers a contiguous range and the flags describe a set.
    Narrowing at either end is fine; a hole is refused by name.

    Offering 1.2 after being told not to is the quiet disagreement this
    whole module exists not to do.
    """
    context = allcrypt_ssl.create_default_context()
    context.minimum_version = allcrypt_ssl.TLSVersion.TLSv1
    with pytest.raises(ValueError) as caught:
        context.options |= allcrypt_ssl.OP_NO_TLSv1_2
    assert "gap in the middle" in str(caught.value)


def test_an_empty_version_window_is_refused_with_both_reasons_named():
    context = allcrypt_ssl.create_default_context()
    with pytest.raises(ValueError) as caught:
        context.options |= (allcrypt_ssl.OP_NO_TLSv1_2
                            | allcrypt_ssl.OP_NO_TLSv1_3)
    message = str(caught.value)
    assert "no TLS version at all" in message
    assert "OP_NO_TLSv1_2" in message and "OP_NO_TLSv1_3" in message


def test_asking_for_sslv3_by_version_just_works():
    """Every context starts with `OP_NO_SSLv3` set, and lowering
    `minimum_version` to SSLv3 nevertheless reaches it.

    Not because the flag is ignored: **assigning `minimum_version`
    clears the matching `OP_NO_*` bits**, which is what OpenSSL does and
    what the standard library inherits. So the contradiction a caller
    would otherwise have to resolve by hand resolves itself, and asking
    for SSLv3 stays one decision rather than two. Asserted because it is
    surprising, and because a future change to the setter would
    otherwise silently make the documented SSLv3 path stop working.
    """
    context = allcrypt_ssl.create_default_context()
    assert context.options & allcrypt_ssl.OP_NO_SSLv3

    context.minimum_version = allcrypt_ssl.TLSVersion.SSLv3
    assert not (context.options & allcrypt_ssl.OP_NO_SSLv3), \
        "assigning minimum_version no longer clears the option"
    assert context._version_window()[0] == allcrypt_ssl.TLSVersion.SSLv3

    # And the constructor whose purpose is reaching old boxes has
    # cleared it regardless, so it never depends on that side effect.
    legacy = allcrypt_ssl.create_legacy_context()
    assert not (legacy.options & allcrypt_ssl.OP_NO_SSLv3)


def test_setting_op_no_sslv3_after_the_version_is_refused():
    """The other order is a real contradiction and is refused by name.

    This is the path the error message exists for: the caller has said
    SSLv3 and then said not-SSLv3, and approximating either way would be
    this module disagreeing with its own configuration.
    """
    context = allcrypt_ssl.create_default_context()
    context.minimum_version = allcrypt_ssl.TLSVersion.SSLv3
    context.maximum_version = allcrypt_ssl.TLSVersion.SSLv3
    with pytest.raises(ValueError) as caught:
        context.options |= allcrypt_ssl.OP_NO_SSLv3
    message = str(caught.value)
    assert "no TLS version at all" in message
    assert "OP_NO_SSLv3" in message


def test_clearing_middlebox_compat_is_refused():
    """We always send the TLS 1.3 compatibility ChangeCipherSpec, so a
    context recording the request without acting on it would be lying
    about what goes on the wire."""
    context = allcrypt_ssl.create_default_context()
    with pytest.raises(ValueError) as caught:
        context.options &= ~allcrypt_ssl.OP_ENABLE_MIDDLEBOX_COMPAT
    assert "ChangeCipherSpec" in str(caught.value)


@pytest.mark.parametrize("flag", ["VERIFY_CRL_CHECK_LEAF",
                                  "VERIFY_CRL_CHECK_CHAIN",
                                  "VERIFY_ALLOW_PROXY_CERTS"])
def test_verify_flags_we_cannot_honour_raise_by_name(flag):
    """Nothing here fetches a CRL, so the flag could only mean "fail
    every chain" or "check nothing" - and a caller who asks for
    revocation checking and is told nothing is a caller who believes
    revoked certificates are being refused.

    The name in the error is the flag the caller set: `CHECK_CHAIN` is
    `CHECK_LEAF` with another bit, so a truthiness test would report the
    wrong one - the right refusal with the wrong reason.
    """
    context = allcrypt_ssl.create_default_context()
    with pytest.raises(ValueError) as caught:
        context.verify_flags |= getattr(allcrypt_ssl, flag)
    assert str(caught.value).startswith(flag + " cannot be honoured")


def test_the_verify_flags_we_do_hold_report_as_already_true():
    context = allcrypt_ssl.create_default_context()
    context.verify_flags |= (allcrypt_ssl.VERIFY_X509_STRICT
                             | allcrypt_ssl.VERIFY_X509_PARTIAL_CHAIN)
    report = context.verify_flags_report()
    assert report["VERIFY_X509_STRICT"] == "already true"
    assert report["VERIFY_X509_PARTIAL_CHAIN"] == "already true"
    assert "unknown" not in report.values()


# ------------------------------------------------------------- a real server ---

@pytest.fixture(scope="module")
def server_files(tmp_path_factory):
    directory = tmp_path_factory.mktemp("dropin")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(1)
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=365))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                  critical=True)
                   .add_extension(
                       x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                       critical=False)
                   .sign(key, hashes.SHA256()))
    certfile = directory / "cert.pem"
    keyfile = directory / "key.pem"
    certfile.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return str(certfile), str(keyfile)


class HttpsServer:
    """One OpenSSL-backed HTTPS responder on loopback.

    The *server* is the standard library on purpose: a test where both
    ends are ours would agree with itself about anything.
    """

    def __init__(self, certfile, keyfile, connections=4, maximum=None):
        self.context = real_ssl.SSLContext(real_ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile, keyfile)
        if maximum is not None:
            self.context.maximum_version = maximum
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        self.connections = connections
        self.errors = []
        self.bindings = []

    def __enter__(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return self

    def _run(self):
        for _ in range(self.connections):
            try:
                raw, _ = self.listener.accept()
            except OSError:
                return
            try:
                with self.context.wrap_socket(raw, server_side=True) as tls:
                    self.bindings.append(tls.get_channel_binding("tls-unique"))
                    tls.recv(8192)
                    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                b"Connection: close\r\n\r\nok")
            except Exception as problem:            # noqa: BLE001
                self.errors.append(repr(problem))

    def __exit__(self, *exc):
        try:
            self.listener.close()
        except OSError:
            pass
        self.thread.join(timeout=10)


def test_http_client_through_the_substituted_module(server_files):
    """`http.client` is what every other HTTP library sits on."""
    certfile, _ = server_files
    with HttpsServer(certfile, _, connections=1) as server:
        saved = sys.modules.get("ssl")
        sys.modules["ssl"] = allcrypt_ssl
        try:
            import http.client
            context = allcrypt_ssl.create_default_context(cafile=certfile)
            connection = http.client.HTTPSConnection(
                "localhost", server.port, context=context, timeout=10)
            connection.request("GET", "/")
            response = connection.getresponse()
            assert response.status == 200
            assert response.read() == b"ok"
            assert context.backend_in_use == "allcrypt", "fell back to OpenSSL"
            connection.close()
        finally:
            if saved is not None:
                sys.modules["ssl"] = saved
    assert not server.errors, server.errors


def test_urllib3_and_requests_through_the_substituted_module(server_files):
    """The two libraries almost everything actually uses.

    Run in a subprocess, because substituting `sys.modules["ssl"]` after
    `urllib3` has already imported the real one would test neither -
    and un-importing it inside this process would poison every later
    test in the run.
    """
    pytest.importorskip("urllib3")
    pytest.importorskip("requests")
    certfile, keyfile = server_files

    program = r"""
import socket, ssl as real_ssl, sys, threading
import allcrypt_ssl
sys.modules["ssl"] = allcrypt_ssl

certfile, keyfile = sys.argv[1], sys.argv[2]
context = real_ssl.SSLContext(real_ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile, keyfile)
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0)); listener.listen(8)
port = listener.getsockname()[1]

def serve():
    for _ in range(4):
        try:
            raw, _ = listener.accept()
        except OSError:
            return
        try:
            with context.wrap_socket(raw, server_side=True) as tls:
                tls.recv(8192)
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                            b"Connection: close\r\n\r\nok")
        except Exception:
            pass
threading.Thread(target=serve, daemon=True).start()

seen = []
original = allcrypt_ssl.SSLContext.wrap_socket
def spy(self, *args, **kwargs):
    result = original(self, *args, **kwargs)
    seen.append((self.backend_in_use, type(result).__module__))
    return result
allcrypt_ssl.SSLContext.wrap_socket = spy

import requests
response = requests.get("https://localhost:%d/" % port, verify=certfile, timeout=15)
assert response.status_code == 200, response.status_code
assert response.text == "ok", response.text
assert seen, "requests never went through allcrypt_ssl.wrap_socket"
for backend, module in seen:
    assert backend == "allcrypt", (backend, module)
    assert module == "allcrypt_ssl", (backend, module)
print("OK", len(seen))
"""
    import os
    environment = dict(os.environ)
    # The child has to find the same `allcrypt_ssl` this run imported,
    # wherever that came from - a checkout, an installed wheel, or a
    # PYTHONPATH somebody set.
    roots = [os.path.dirname(allcrypt_ssl.__file__)]
    if environment.get("PYTHONPATH"):
        roots.append(environment["PYTHONPATH"])
    environment["PYTHONPATH"] = os.pathsep.join(roots)
    finished = subprocess.run(
        [sys.executable, "-c", program, certfile, keyfile],
        capture_output=True, text=True, timeout=180, env=environment)
    assert finished.returncode == 0, finished.stdout + finished.stderr
    assert finished.stdout.startswith("OK"), finished.stdout


# ------------------------------------------------------------ channel binding ---

@pytest.mark.parametrize("maximum", [real_ssl.TLSVersion.TLSv1_2,
                                     real_ssl.TLSVersion.TLSv1_3],
                         ids=["tls12", "tls13"])
def test_tls_unique_matches_what_the_peer_computed(server_files, maximum):
    """**The only check that means anything for a channel binding**: the
    other end has to arrive at the same bytes, or an authentication bound
    to it fails looking like a bad password.

    The selection rule is OpenSSL's - our own Finished unless the session
    was resumed, then the peer's - and a client that always used its own
    agrees with itself on every handshake and with the server on only
    some of them.
    """
    certfile, keyfile = server_files
    with HttpsServer(certfile, keyfile, connections=1, maximum=maximum) as server:
        context = allcrypt_ssl.create_default_context(cafile=certfile)
        context.maximum_version = allcrypt_ssl.TLSVersion(maximum.value)
        raw = socket.create_connection(("127.0.0.1", server.port), timeout=10)
        with context.wrap_socket(raw, server_hostname="localhost") as tls:
            assert context.backend_in_use == "allcrypt"
            ours = tls.get_channel_binding("tls-unique")
            tls.sendall(b"GET / HTTP/1.0\r\n\r\n")
            tls.recv(4096)
    assert not server.errors, server.errors
    assert ours is not None
    assert ours == server.bindings[0], "the two ends computed different bindings"


def test_an_unknown_channel_binding_type_raises(server_files):
    certfile, keyfile = server_files
    with HttpsServer(certfile, keyfile, connections=1) as server:
        context = allcrypt_ssl.create_default_context(cafile=certfile)
        raw = socket.create_connection(("127.0.0.1", server.port), timeout=10)
        with context.wrap_socket(raw, server_hostname="localhost") as tls:
            with pytest.raises(ValueError):
                tls.get_channel_binding("tls-server-end-point")
            tls.sendall(b"GET / HTTP/1.0\r\n\r\n")
            tls.recv(4096)


def test_tls_exporter_matches_openssls_own_exporter(server_files):
    """RFC 9266's binding, against `openssl s_server -keymatexport`.

    This is the only independent opinion available: this Python's
    OpenSSL is too old to expose `tls-exporter` through `ssl`, so the
    command-line tool is what can answer. Without it the exporter would
    be new key-schedule code checked only against itself - two
    derivations where every intermediate value is the right length, so a
    mistake produces a perfectly plausible wrong answer.
    """
    certfile, keyfile = server_files
    label = "EXPORTER-Channel-Binding"

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()

    # `s_server` exits when its stdin reaches EOF, so it is given one
    # that stays open for the length of the test.
    keep_open = subprocess.Popen(["sleep", "30"], stdout=subprocess.PIPE)
    server = subprocess.Popen(
        ["openssl", "s_server", "-accept", str(port), "-cert", certfile,
         "-key", keyfile, "-tls1_3", "-naccept", "1",
         "-keymatexport", label, "-keymatexportlen", "32"],
        stdin=keep_open.stdout, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True)

    try:
        deadline = time.time() + 15
        connected = None
        while time.time() < deadline:
            try:
                connected = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                time.sleep(0.2)
        assert connected is not None, "openssl s_server never accepted"

        context = allcrypt_ssl.create_default_context(cafile=certfile)
        context.minimum_version = allcrypt_ssl.TLSVersion.TLSv1_3
        with context.wrap_socket(connected, server_hostname="localhost") as tls:
            assert tls.version() == "TLSv1.3"
            ours = tls.get_channel_binding("tls-exporter")
            tls.sendall(b"hello\n")
            time.sleep(1.0)
        output = server.communicate(timeout=20)[0]
    finally:
        for process in (server, keep_open):
            if process.poll() is None:
                process.kill()

    import re
    found = re.search(r"Keying material:\s*([0-9A-Fa-f]+)", output)
    assert found, "openssl printed no keying material:\n" + output[:2000]
    assert ours == bytes.fromhex(found.group(1)), (
        "our tls-exporter differs from OpenSSL's for the same connection")


def test_tls_unique_and_tls_exporter_are_not_each_others_fallback(server_files):
    """They belong to different versions, and a binding that is merely
    *a* value would authenticate the wrong connection with nothing to
    report it.

    `tls-unique` is returned at 1.3 as well, which is a deliberate match
    with OpenSSL rather than an oversight - see `docs/pitfalls.md`.
    `tls-exporter` is the one that is sound there, and it is `None`
    below 1.3 because RFC 9266 does not define it.
    """
    certfile, keyfile = server_files
    with HttpsServer(certfile, keyfile, connections=1,
                     maximum=real_ssl.TLSVersion.TLSv1_2) as server:
        context = allcrypt_ssl.create_default_context(cafile=certfile)
        context.maximum_version = allcrypt_ssl.TLSVersion.TLSv1_2
        raw = socket.create_connection(("127.0.0.1", server.port), timeout=10)
        with context.wrap_socket(raw, server_hostname="localhost") as tls:
            assert tls.version() == "TLSv1.2"
            assert tls.get_channel_binding("tls-unique") is not None
            assert tls.get_channel_binding("tls-exporter") is None, \
                "tls-exporter is not defined below TLS 1.3"
            tls.sendall(b"GET / HTTP/1.0\r\n\r\n")
            tls.recv(4096)
