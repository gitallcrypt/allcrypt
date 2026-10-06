"""The proxy binary, end to end on loopback.

Three TLS stacks in one test: a real OpenSSL **origin server**, the
`allcrypt-proxy` binary in the middle terminating on both sides, and a
real OpenSSL **client** in front of it. Everything between the two
OpenSSLs is this library - two complete handshakes, two record layers,
and a certificate built while the connection was being set up.

What is new here, beyond the two halves already tested on their own
(`test_tls_handshake.py` for the client, `test_tls_server.py` for the
server), is the **mirroring**. The proxy does not hand the browser a
blanket padlock; it presents a certificate as trustworthy as the one the
origin actually sent, with the subject, the alternative names, the
validity window and the serial copied across. So the assertions here are
about what the client is *allowed to conclude*: an expired origin must
still look expired, a self-signed one self-signed, and a good one good.

The binary is run for real, as a subprocess, because that is what a
person will run. A `Proxy` object constructed in-process would test a
wiring that nobody uses.

Everything is on 127.0.0.1 and nothing here touches the network - see
the note at the top of `conftest.py`.
"""

import datetime
import http.client
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


ROOT = pathlib.Path(__file__).resolve().parent.parent


def binary():
    """The built proxy - **the most recently built of them**.

    Not skipped when absent: a test that quietly vanishes because
    somebody forgot to build is a hole that looks like a pass. It fails
    and says what to run.

    This used to prefer `release` outright, and that cost an afternoon:
    a release binary built hours earlier shadowed the debug build that
    had just been made, so a change under test was not in the program
    being run and the failure was in the old code's words. Whichever
    was built last is the one somebody just made.
    """
    built = [path for path in [ROOT / "target" / "release" / "allcrypt-proxy",
                               ROOT / "target" / "debug" / "allcrypt-proxy"]
             if path.exists()]
    if not built:
        pytest.fail("allcrypt-proxy is not built. Run `cargo build --release`.",
                    pytrace=False)
    return str(max(built, key=lambda path: path.stat().st_mtime))


# ------------------------------------------------------------ the origin ---

def certificate_for(key, common_name="localhost", *, days_valid=365,
                    days_ago=1, issuer_name=None, issuer_key=None,
                    san=None):
    """A certificate from `cryptography`.

    The origin stands in for a box out there that we did not make, so
    its certificate is not built with our own builder: one both ends of
    the test wrote is one nobody else has an opinion about.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = (x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
              if issuer_name else subject)
    builder = (x509.CertificateBuilder()
               .subject_name(subject).issuer_name(issuer)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=days_ago))
               .not_valid_after(now + datetime.timedelta(days=days_valid))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                              critical=True)
               .add_extension(
                   x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                   critical=False)
               .add_extension(
                   x509.SubjectAlternativeName(
                       san if san is not None
                       else [x509.DNSName(common_name)]),
                   critical=False))
    return builder.sign(issuer_key or key, hashes.SHA256())


class Origin:
    """A real OpenSSL HTTPS server on 127.0.0.1, in a thread.

    Deliberately the standard library's: something this library did not
    write has to be at the far end, or the test is our record layer
    talking to itself with a proxy in between.
    """

    def __init__(self, *, identity=None, ciphers=None, maximum_version=None,
                 minimum_version=None, body=b"hello from the old box"):
        if identity is None:
            key = ec.generate_private_key(ec.SECP256R1())
            identity = (key, certificate_for(key))
        self.key, self.certificate = identity
        self.pem = self.certificate.public_bytes(
            serialization.Encoding.PEM).decode()
        self.body = body
        # What the far end saw when a handshake did not finish. The
        # difference between "alert" and an EOF is the whole of
        # `test_a_refusal_reaches_the_server_as_an_alert`.
        self.handshake_errors = []

        handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
        handle.write(self.pem)
        handle.write(self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()).decode())
        handle.close()
        self._path = handle.name

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # The ciphers first: @SECLEVEL=0 is what lets a weak suite or an
        # old version be used at all, and load_cert_chain checks the key
        # against the level set at the time.
        if ciphers:
            context.set_ciphers(ciphers)
        context.load_cert_chain(self._path)
        if minimum_version:
            context.minimum_version = minimum_version
        if maximum_version:
            context.maximum_version = maximum_version
        self._context = context

        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self.address = self._listener.getsockname()
        self.port = self.address[1]
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                raw, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(raw,),
                             daemon=True).start()

    def _handle(self, raw):
        try:
            with self._context.wrap_socket(raw, server_side=True) as tls:
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = tls.recv(4096)
                    if not chunk:
                        return
                    request += chunk
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                            b"Connection: close\r\n\r\n%s"
                            % (len(self.body), self.body))
        except (OSError, ssl.SSLError) as error:
            self.handshake_errors.append(repr(error))
        finally:
            try:
                raw.close()
            except OSError:
                pass

    def wait_for_handshake_error(self, timeout=10.0):
        """The recorded handshake errors, once there is at least one.

        `handshake_errors` is appended by the per-connection thread in
        `_handle`, so a test that reads it the instant the *proxy* logs
        something can beat the server's own thread to it - the proxy
        having sent an alert says nothing about this end having read it
        yet. `test_a_refusal_reaches_the_server_as_an_alert` failed once
        that way, on a run sharing two cores with a `cargo test`, and
        passed twelve times in a row afterwards; the race is narrow and it
        is plainly there in `_handle`, which is reason enough to wait
        rather than to keep re-running it.

        Returns a snapshot rather than the live list, and returns whatever
        it has when the timeout expires rather than raising - the caller's
        own assertion is the one that should report the failure, because it
        knows what it was looking for.
        """
        deadline = time.time() + timeout
        while time.time() < deadline and not self.handshake_errors:
            time.sleep(0.05)
        return list(self.handshake_errors)

    def close(self):
        self._stop = True
        try:
            self._listener.close()
        except OSError:
            pass
        try:
            os.unlink(self._path)
        except OSError:
            pass


# ------------------------------------------------------------- the proxy ---

class ProxyProcess:
    """The `allcrypt-proxy` binary, run for real."""

    def __init__(self, *extra, ca_dir=None, quiet_default=False):
        self.directory = ca_dir or tempfile.mkdtemp(prefix="allcrypt-proxy-")
        self._own_dir = ca_dir is None
        port = free_port()
        self.port = port
        # `quiet_default` runs it the way a person first runs it, with
        # no flags. It is how the tests about the default level say
        # something that "--verbose everywhere" cannot.
        verbosity = [] if quiet_default else ["--verbose"]
        self.process = subprocess.Popen(
            [binary(), "--port", str(port), "--ca-dir", self.directory,
             *verbosity, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Drained in a thread rather than read at the end: a PIPE that
        # fills blocks the process writing into it, and a proxy that
        # stops mid-connection because nobody read its log is a hang
        # with no explanation.
        self.log = []
        self._reader = threading.Thread(target=self._drain, daemon=True)
        self._reader.start()
        self._wait_until_listening()

    def _drain(self):
        for line in self.process.stderr:
            self.log.append(line.decode("utf-8", "replace").rstrip())

    def wait_for_log(self, needle, timeout=10.0):
        """The first logged line containing `needle`.

        The proxy writes its verdict as it goes, so a test that looks
        immediately after the fetch can beat the write.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            for line in list(self.log):
                if needle in line:
                    return line
            time.sleep(0.05)
        raise AssertionError(
            f"no log line containing {needle!r}; saw:\n" + "\n".join(self.log))

    def wait_for_verdict(self, host="localhost", timeout=10.0):
        """The line carrying what was made of the server's certificate.

        The verdict is the only line with the verdict in brackets, and
        asking for it by shape rather than by hostname is deliberate:
        the tests here used to wait for the first line mentioning
        "localhost", which was the verdict until the log learned to
        print the CONNECT as well - and then it was a line that says
        nothing about trust, and the assertion about the verdict was
        being made against it.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            for line in list(self.log):
                if host in line and "[" in line and line.rstrip().endswith("]"):
                    return line
            time.sleep(0.05)
        raise AssertionError(
            "no verdict line for %r; saw:\n" % host + "\n".join(self.log))

    def _wait_until_listening(self, timeout=20.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.process.poll() is not None:
                out = self.process.stderr.read().decode("utf-8", "replace")
                raise AssertionError("the proxy exited at once:\n" + out)
            try:
                socket.create_connection(("127.0.0.1", self.port),
                                         timeout=0.5).close()
                # The CA is written before the listener opens, so once
                # the port answers the file is there.
                if os.path.exists(os.path.join(self.directory, "ca.pem")):
                    return
            except OSError:
                pass
            time.sleep(0.05)
        raise AssertionError("the proxy never started listening")

    @property
    def ca_pem(self):
        with open(os.path.join(self.directory, "ca.pem")) as handle:
            return handle.read()

    def close(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
        if self._own_dir:
            shutil.rmtree(self.directory, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def fetch(proxy, origin, *, trust=None, host="localhost", timeout=20):
    """Fetch through the proxy with a real OpenSSL client.

    `set_tunnel` is the browser's CONNECT. `trust` is the PEM the client
    will verify against - the proxy's CA for the ordinary case, and
    `None` for a client that trusts nothing, which is how a mirrored
    warning is observed.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if trust is None:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context.load_verify_locations(cadata=trust)
    connection = http.client.HTTPSConnection("127.0.0.1", proxy.port,
                                             context=context, timeout=timeout)
    connection.set_tunnel(host, origin.port)
    try:
        connection.request("GET", "/")
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def presented_certificate(proxy, origin, host="localhost", timeout=20):
    """The certificate the proxy shows, fetched without judging it.

    Verification off on purpose: the point is to look at what was sent,
    including in the cases where a client would refuse it.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=timeout)
    try:
        raw.sendall(b"CONNECT %s:%d HTTP/1.1\r\n\r\n"
                    % (host.encode(), origin.port))
        answer = raw.recv(4096)
        assert b"200" in answer, answer
        with context.wrap_socket(raw, server_hostname=host) as tls:
            return x509.load_der_x509_certificate(
                tls.getpeercert(binary_form=True))
    finally:
        try:
            raw.close()
        except OSError:
            pass


@pytest.fixture
def origin():
    server = Origin()
    yield server
    server.close()


# -------------------------------------------------------------- the point ---

def test_a_page_comes_back_through_the_proxy(origin):
    """OpenSSL client -> our server -> our client -> OpenSSL server.

    Both handshakes complete and both record layers carry the traffic.
    """
    with ProxyProcess("--root", pem_file(origin)) as proxy:
        status, body = fetch(proxy, origin, trust=proxy.ca_pem)
    assert status == 200
    assert body == b"hello from the old box"


def pem_file(origin):
    """The origin's certificate on disk, for `--root`.

    The narrowest way to reach a box with its own certificate, and the
    one the help text puts first: not a relaxation at all, but
    authentication against a certificate chosen deliberately.
    """
    handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    handle.write(origin.pem)
    handle.close()
    return handle.name


# ---------------------------------------------------------- the mirroring ---

def test_the_mirror_carries_the_origins_name_and_dates(origin):
    """**The reason this proxy is different.**

    It does not hand the client a certificate of its own invention. The
    subject, the alternative names, the serial and the validity window
    are the origin's, so the client judges the same facts it would have
    judged talking directly.
    """
    with ProxyProcess("--root", pem_file(origin)) as proxy:
        presented = presented_certificate(proxy, origin)

    real = origin.certificate
    assert presented.subject == real.subject
    assert presented.serial_number == real.serial_number
    assert presented.not_valid_before_utc == real.not_valid_before_utc
    assert presented.not_valid_after_utc == real.not_valid_after_utc

    mirrored_sans = presented.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    real_sans = real.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    assert list(mirrored_sans) == list(real_sans)

    # The key is the one thing that cannot be mirrored: the proxy has to
    # hold the private half and does not have the origin's. Asserted so
    # the limitation is recorded rather than discovered.
    assert presented.public_key().public_numbers() != \
        real.public_key().public_numbers()


def test_a_good_origin_is_accepted_by_a_client_trusting_only_the_ca(origin):
    """Trusted upstream -> signed by the installed CA -> no warning."""
    with ProxyProcess("--root", pem_file(origin)) as proxy:
        presented = presented_certificate(proxy, origin)
        ca = x509.load_pem_x509_certificate(proxy.ca_pem.encode())
        assert presented.issuer == ca.subject

        status, _ = fetch(proxy, origin, trust=proxy.ca_pem)
    assert status == 200


def test_a_self_signed_origin_mirrors_as_self_signed(origin):
    """No `--root`, so the origin's self-signed certificate does not
    verify - and the client is shown a self-signed certificate rather
    than one the installed CA vouches for.

    Both halves matter: the shape is right, *and* a client trusting the
    CA refuses it. A proxy that signed this with its own CA would give
    the user a padlock on an unauthenticated connection.
    """
    with ProxyProcess() as proxy:
        presented = presented_certificate(proxy, origin)
        assert presented.issuer == presented.subject, \
            "a self-signed origin was not mirrored as self-signed"
        assert presented.issuer == origin.certificate.subject

        with pytest.raises((ssl.SSLError, OSError,
                            http.client.HTTPException)):
            fetch(proxy, origin, trust=proxy.ca_pem)


def test_an_origin_from_an_unknown_ca_mirrors_as_untrusted(origin_from_ca):
    """Not self-signed, and not trusted either: the mirror is issued by
    a CA the client has never seen, which is what the origin's own
    issuer was."""
    origin, _ = origin_from_ca
    with ProxyProcess() as proxy:
        presented = presented_certificate(proxy, origin)
        ca = x509.load_pem_x509_certificate(proxy.ca_pem.encode())
        assert presented.issuer != ca.subject, \
            "an untrusted origin was mirrored as a trusted one"
        assert presented.issuer != presented.subject, \
            "an origin signed by a CA was mirrored as self-signed"

        with pytest.raises((ssl.SSLError, OSError,
                            http.client.HTTPException)):
            fetch(proxy, origin, trust=proxy.ca_pem)


@pytest.fixture
def origin_from_ca():
    """An origin whose certificate was issued by a CA nobody trusts."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = certificate_for(ca_key, "An Unknown CA")
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = certificate_for(leaf_key, "localhost", issuer_name="An Unknown CA",
                           issuer_key=ca_key)
    server = Origin(identity=(leaf_key, leaf))
    yield server, ca_cert
    server.close()


def test_an_expired_origin_mirrors_as_expired(origin):
    """The dates are copied, so the client refuses for the same reason
    it would have refused the origin - and says so in those words."""
    key = ec.generate_private_key(ec.SECP256R1())
    expired = certificate_for(key, "localhost", days_valid=-400, days_ago=800)
    origin.close()
    origin = Origin(identity=(key, expired))
    try:
        with ProxyProcess("--root", pem_file(origin)) as proxy:
            presented = presented_certificate(proxy, origin)
            assert presented.not_valid_after_utc == expired.not_valid_after_utc
            assert presented.not_valid_after_utc < \
                datetime.datetime.now(datetime.timezone.utc), \
                "the mirror of an expired certificate is not expired"

            with pytest.raises((ssl.SSLError, OSError,
                                http.client.HTTPException)):
                fetch(proxy, origin, trust=proxy.ca_pem)
    finally:
        origin.close()


def test_an_origin_for_another_name_mirrors_with_that_name(origin):
    """A certificate for the wrong host stays wrong. The proxy must not
    quietly fix it by issuing one for the name the client asked for."""
    key = ec.generate_private_key(ec.SECP256R1())
    wrong = certificate_for(key, "somewhere-else.test")
    origin.close()
    origin = Origin(identity=(key, wrong))
    try:
        with ProxyProcess("--root", pem_file(origin)) as proxy:
            presented = presented_certificate(proxy, origin)
            sans = presented.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value
            assert sans.get_values_for_type(x509.DNSName) == \
                ["somewhere-else.test"], \
                "the proxy issued a certificate for the name asked for"

            with pytest.raises((ssl.SSLError, OSError,
                                http.client.HTTPException)):
                fetch(proxy, origin, trust=proxy.ca_pem)
    finally:
        origin.close()


def test_the_verdict_is_reported_and_is_about_this_host(origin):
    """`--verbose` says what was made of the server's certificate, and a
    certificate for the wrong host is **not** "verified".

    Worth its own test because nothing else observes the hostname half
    of the judgement: the mirror copies the origin's names, so a client
    refuses a wrong-name certificate whatever the proxy concluded. That
    makes the check invisible - and an invisible check is one that can
    stop working without anyone noticing. Found exactly that way, by
    removing the hostname from the verdict and watching all twenty-four
    tests pass.

    It matters for two reasons. The line is what an operator reads to
    know why a page will not load; and a "verified" verdict is what
    makes the proxy sign with the CA the browser trusts, so it should
    never be reached for a certificate that is wrong for this host.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    wrong = certificate_for(key, "somewhere-else.test")
    origin.close()
    origin = Origin(identity=(key, wrong))
    try:
        root = pem_file(origin)
        with ProxyProcess("--root", root) as proxy:
            try:
                fetch(proxy, origin, trust=proxy.ca_pem)
            except Exception:
                pass
            line = proxy.wait_for_verdict()
        assert "verified" not in line or "untrusted" in line, line
    finally:
        origin.close()

    # The control: the same kind of certificate, trusted the same way,
    # but for the host actually asked for. Without this the assertion
    # above would pass on a proxy that never says "verified" at all.
    #
    # The name has to be one that resolves - the proxy connects to the
    # host in the CONNECT line - so the control varies the certificate
    # rather than the request.
    right = Origin()
    try:
        with ProxyProcess("--root", pem_file(right)) as proxy:
            fetch(proxy, right, trust=proxy.ca_pem)
            line = proxy.wait_for_verdict()
        assert "verified" in line, line
        assert "untrusted" not in line, line
    finally:
        right.close()


def test_every_verdict_produces_a_different_issuer(origin, origin_from_ca):
    """Stated as a comparison, so a mistake that made two verdicts
    behave alike cannot pass. A test of each one alone would not see
    that."""
    untrusted_origin, _ = origin_from_ca
    good = Origin()
    try:
        with ProxyProcess("--root", pem_file(good)) as proxy:
            trusted_issuer = presented_certificate(proxy, good).issuer
        with ProxyProcess() as proxy:
            ca = x509.load_pem_x509_certificate(proxy.ca_pem.encode())
            self_signed = presented_certificate(proxy, origin)
            unknown = presented_certificate(proxy, untrusted_origin)

        assert self_signed.issuer == self_signed.subject
        assert unknown.issuer != unknown.subject
        assert unknown.issuer != ca.subject
        assert self_signed.issuer != unknown.issuer
    finally:
        good.close()


# ------------------------------------------- reaching the things it is for ---

# These rows are also the regression test for a bug that only appeared when
# the proxy's browser-facing side learned TLS 1.3.
#
# `handshake_server` reads whole TCP segments, and at 1.3 the client's
# Finished and its first request are one flight - so the request is normally
# already decrypted and sitting in the connection by the time the handshake
# returns. The relay then read the socket first and blocked forever on bytes
# that were never coming, because it was holding the request the peer was
# waiting for a reply to.
#
# It showed up here as a *flaky* row rather than a failing one, since whether
# the two land in one segment is the kernel's choice: about one row in six,
# moving between runs. The symptom was a read timeout with no error anywhere.
# `Peer::pending` in `src/main.rs` is the fix, and the visible effect is that
# this file went from twenty-one seconds to under four - the difference was
# timeouts.

@pytest.mark.parametrize("suite,key_kind", [
    ("AES128-SHA", "rsa"),                       # RSA key transport, CBC
    ("AES256-SHA", "rsa"),
    ("ECDHE-RSA-AES128-SHA", "rsa"),
    ("ECDHE-RSA-AES128-GCM-SHA256", "rsa"),
    ("ECDHE-ECDSA-AES128-SHA", "ec"),
    ("ECDHE-ECDSA-AES128-GCM-SHA256", "ec"),
])
def test_an_origin_speaking_something_old_is_still_reached(suite, key_kind):
    """**The reason the proxy exists.**

    A modern client cannot be made to speak these; here it does not have
    to. It speaks AES-GCM and TLS 1.2 to the proxy, and the proxy speaks
    the old thing onwards.

    Every row must be *accepted* - a row that is merely refused proves
    nothing about reachability, which is the trap `check_live.py` has a
    whole section about.

    The key type is part of the row because it has to match the suite:
    `AES128-SHA` is RSA key transport and needs an RSA certificate, and
    an EC one makes the origin answer handshake_failure. Getting that
    wrong looks exactly like a broken client.
    """
    key = (rsa.generate_private_key(public_exponent=65537, key_size=2048)
           if key_kind == "rsa" else ec.generate_private_key(ec.SECP256R1()))
    origin = Origin(identity=(key, certificate_for(key)),
                    ciphers=suite + ":@SECLEVEL=0",
                    minimum_version=ssl.TLSVersion.TLSv1_2,
                    maximum_version=ssl.TLSVersion.TLSv1_2)
    try:
        with ProxyProcess("--legacy", "--root", pem_file(origin)) as proxy:
            status, body = fetch(proxy, origin, trust=proxy.ca_pem)
        assert status == 200, suite
        assert body == b"hello from the old box"
    finally:
        origin.close()


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1,
                                     ssl.TLSVersion.TLSv1_1])
def test_an_origin_on_an_old_protocol_version_is_reached(version):
    """TLS 1.0 and 1.1, which a current browser will not speak at all.

    The client in front knows nothing about what happens behind the
    proxy: it gets TLS 1.2.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    origin = Origin(identity=(key, certificate_for(key)),
                    ciphers="AES128-SHA:@SECLEVEL=0",
                    minimum_version=version, maximum_version=version)
    try:
        with ProxyProcess("--legacy", "--root", pem_file(origin)) as proxy:
            status, body = fetch(proxy, origin, trust=proxy.ca_pem)
        assert status == 200
        assert body == b"hello from the old box"
    finally:
        origin.close()


def test_a_1024_bit_rsa_origin_is_reached_with_legacy(origin):
    """A key nobody would issue today, on a box nobody will reissue for."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    origin.close()
    origin = Origin(identity=(key, certificate_for(key)),
                    ciphers="AES128-SHA:@SECLEVEL=0",
                    minimum_version=ssl.TLSVersion.TLSv1_2,
                    maximum_version=ssl.TLSVersion.TLSv1_2)
    try:
        with ProxyProcess("--legacy", "--root", pem_file(origin)) as proxy:
            status, body = fetch(proxy, origin, trust=proxy.ca_pem)
        assert status == 200
        assert body == b"hello from the old box"
    finally:
        origin.close()


def test_a_large_body_crosses_intact(origin):
    """Several records in each direction, so a sequence number that
    only works for the first one is caught."""
    payload = bytes((i * 7 + 3) & 0xff for i in range(300_000))
    origin.close()
    origin = Origin(body=payload)
    try:
        with ProxyProcess("--root", pem_file(origin)) as proxy:
            status, body = fetch(proxy, origin, trust=proxy.ca_pem)
        assert status == 200
        assert body == payload
    finally:
        origin.close()


def test_several_connections_to_one_host(origin):
    """A browser opens several at once. The certificate is cached, so
    they must all see the same one and all work."""
    with ProxyProcess("--root", pem_file(origin)) as proxy:
        seen = set()
        for _ in range(5):
            presented = presented_certificate(proxy, origin)
            seen.add(presented.public_bytes(serialization.Encoding.DER))
            status, body = fetch(proxy, origin, trust=proxy.ca_pem)
            assert status == 200
            assert body == b"hello from the old box"
    assert len(seen) == 1, "a different certificate per connection"


# ------------------------------------------------------------- the shapes ---

def test_the_ca_is_made_once_and_kept(origin):
    """A browser is asked to trust this CA. Regenerating it on restart
    would mean asking again every time, and training the user to say
    yes."""
    directory = tempfile.mkdtemp(prefix="allcrypt-proxy-")
    try:
        with ProxyProcess("--root", pem_file(origin), ca_dir=directory) as first:
            first_pem = first.ca_pem
        with ProxyProcess("--root", pem_file(origin), ca_dir=directory) as again:
            assert again.ca_pem == first_pem
            status, _ = fetch(again, origin, trust=first_pem)
        assert status == 200
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@pytest.mark.skipif(os.name != "posix", reason="no file modes to check")
def test_the_ca_key_is_not_world_readable():
    """It is written with its mode set at creation, not chmod'ed after:
    a chmod leaves a window in which the key is readable, and that
    window is the whole of the exposure."""
    with ProxyProcess() as proxy:
        mode = os.stat(os.path.join(proxy.directory, "ca.key")).st_mode
    assert mode & 0o077 == 0, oct(mode)


def test_a_plain_http_request_is_carried_across(plain_origin):
    """A browser is configured with one proxy for every protocol.

    This used to be a 400 saying "CONNECT only", which does not send the
    plain half of the browser around another way - it breaks it for as
    long as the proxy is set. The box this program exists for usually
    has a plain port too, and its redirect to https:// is how you reach
    the part that needs the proxy at all.
    """
    with ProxyProcess() as proxy:
        raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=20)
        raw.sendall(b"GET http://127.0.0.1:%d/ HTTP/1.1\r\n"
                    b"Host: 127.0.0.1:%d\r\n"
                    b"Connection: close\r\n\r\n"
                    % (plain_origin.port, plain_origin.port))
        answer = b""
        while True:
            chunk = raw.recv(4096)
            if not chunk:
                break
            answer += chunk
        raw.close()
    assert answer.startswith(b"HTTP/1.1 200"), answer
    assert b"plain and unencrypted" in answer, answer
    # The origin form is what a server expects: it is given a path, not
    # the absolute URL the browser sent the proxy.
    assert plain_origin.requests[0].startswith(b"GET / HTTP/1.1"), \
        plain_origin.requests


def test_a_plain_http_request_is_refused_when_that_is_asked_for(plain_origin):
    """`--no-plain-http` for somebody who wants the proxy to carry
    nothing in the clear. The refusal says which option did it, because
    a 400 from a proxy is otherwise indistinguishable from a 400 from
    the site."""
    with ProxyProcess("--no-plain-http") as proxy:
        raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=20)
        raw.sendall(b"GET http://127.0.0.1:%d/ HTTP/1.1\r\n\r\n"
                    % plain_origin.port)
        answer = raw.recv(4096)
        raw.close()
    assert answer.startswith(b"HTTP/1.1 400"), answer
    assert b"--no-plain-http" in answer, answer
    assert not plain_origin.requests


def test_a_request_that_is_not_a_proxy_request_says_so():
    """Opening the proxy's port in a browser as though it were a web
    server. There is no host to forward to, and the reason says what to
    do instead."""
    with ProxyProcess() as proxy:
        raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=20)
        raw.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        answer = raw.recv(4096)
        raw.close()
    assert answer.startswith(b"HTTP/1.1 400"), answer
    assert b"absolute URL" in answer, answer


@pytest.fixture
def plain_origin():
    server = PlainOrigin()
    yield server
    server.close()


class PlainOrigin:
    """An HTTP server with no TLS at all, for the forwarding path."""

    def __init__(self):
        self.requests = []
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self.port = self._listener.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                raw, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(raw,),
                             daemon=True).start()

    def _handle(self, raw):
        try:
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = raw.recv(4096)
                if not chunk:
                    return
                request += chunk
            self.requests.append(request)
            body = b"plain and unencrypted"
            raw.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                        b"Connection: close\r\n\r\n%s" % (len(body), body))
        except OSError:
            pass
        finally:
            try:
                raw.close()
            except OSError:
                pass

    def close(self):
        self._stop = True
        try:
            self._listener.close()
        except OSError:
            pass


def test_a_refusal_reaches_the_server_as_an_alert(origin_rsa):
    """**The bug that made this whole file's logging worth having.**

    Every refusal inside the TLS client queues the fatal alert that says
    which thing was wrong - and the proxy's read/write loop returned on
    the error and dropped the socket, so the queue went out of scope
    unsent. On the wire that is a ServerHello followed by FIN from us:
    the far end learns only that we hung up, and whoever runs it has
    nothing at all to go on.

    `--min-rsa-bits 4096` is a refusal the proxy makes for certain and
    on its own, after the server has committed to a suite, which is the
    position where the alert used to be lost.
    """
    with ProxyProcess("--min-rsa-bits", "4096") as proxy:
        with pytest.raises(Exception):
            fetch(proxy, origin_rsa, trust=None)
        proxy.wait_for_log("sent the server a fatal alert")
    # The proxy's log says *we* sent it; the server's own thread still has
    # to read it, so this waits rather than looking once.
    errors = origin_rsa.wait_for_handshake_error()
    seen = " ".join(errors)
    assert "alert" in seen.lower(), (
        "the server saw %r rather than an alert" % (errors,))


def test_a_refusal_is_logged_without_asking_for_it(origin_rsa):
    """Not everything worth knowing is behind `-v`.

    The proxy used to print a failure only with `--verbose`, and to
    throw the reason away otherwise. Somebody running it because
    something is already broken gets a silent exit and no idea which
    end refused.
    """
    with ProxyProcess("--min-rsa-bits", "4096", quiet_default=True) as proxy:
        with pytest.raises(Exception):
            fetch(proxy, origin_rsa, trust=None)
        line = proxy.wait_for_log("2048 bits")
    assert "4096" in line, line


@pytest.fixture
def origin_rsa():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server = Origin(identity=(key, certificate_for(key)))
    yield server
    server.close()


def test_an_unreachable_upstream_is_reported_before_the_tunnel_opens():
    """502 rather than 200 followed by a failed handshake.

    Answering 200 first means the browser starts a TLS handshake into a
    dead tunnel and reports it as a certificate error - which sends
    whoever is debugging it to the wrong place entirely.
    """
    port = free_port()
    with ProxyProcess() as proxy:
        raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=20)
        raw.sendall(b"CONNECT localhost:%d HTTP/1.1\r\n\r\n" % port)
        answer = raw.recv(4096)
        raw.close()
    assert answer.startswith(b"HTTP/1.1 502"), answer


def test_the_help_says_what_installing_the_ca_means():
    """The one thing a person must understand before running this.

    Asserted because it is the kind of sentence that gets shortened
    later by somebody tidying up.
    """
    output = subprocess.run([binary(), "--help"], capture_output=True,
                            timeout=60).stdout.decode()
    # Whitespace-normalised: the assertion is that the sentence is
    # there, not that it wraps in a particular place. It wrapped
    # between "ANY" and "SITE", and the first version of this test
    # failed on that rather than on anything that matters.
    flat = " ".join(output.upper().split())
    assert "IMPERSONATE ANY SITE TO THAT BROWSER" in flat
    assert "MIRRORS THE REAL ONE" in flat
