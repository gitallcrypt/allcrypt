"""OCSP stapling (RFC 6066 §8), both directions, against OpenSSL.

Stapling is one idea in two wire shapes, and they share almost nothing:

* **TLS 1.2** - an empty `status_request` in the ServerHello saying one is
  coming, and the response in its own `CertificateStatus` message, sent
  immediately after the Certificate.
* **TLS 1.3** - no such message at all. The response is a
  `status_request` extension on the *leaf's certificate entry* (RFC 8446
  §4.4.2.1), which is also the only place the two versions share bytes:
  the extension's body is a `CertificateStatus`.

A server that used the 1.3 shape at 1.2 writes a ServerHello extension
with a body where the client expects none, and one that used the 1.2
shape at 1.3 sends a message nothing is waiting for. Both of those are
invisible between our own two ends, so each half runs against
`ssl.SSLContext` - which can request a staple - and against the `openssl`
binary, which is the only thing here that can *serve* one and the only
thing that will say out loud what it saw.

The responses are built by python-cryptography rather than by this
library, for the reason every differential test here exists: our own
builder and our own parser agreeing proves they agree.
"""

import datetime
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
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import allcrypt

NOW = int(time.time())
PEM = serialization.Encoding.PEM
DER = serialization.Encoding.DER
TLS12 = ssl.TLSVersion.TLSv1_2
TLS13 = ssl.TLSVersion.TLSv1_3


# --------------------------------------------------------------- the PKI ---

class Pki:
    """A CA, a leaf it issued, and OCSP responses about the leaf.

    A real chain rather than a self-signed certificate, because a stapled
    response is checked against the leaf's **issuer** - and a chain of one
    has no issuer, which is a different code path and a different answer.
    """

    def __init__(self, tmp_path):
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "staple CA")])
        now = datetime.datetime.now(datetime.timezone.utc)
        self.ca = (x509.CertificateBuilder()
                   .subject_name(ca_name).issuer_name(ca_name)
                   .public_key(self.ca_key.public_key()).serial_number(11)
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=3650))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                  critical=True)
                   .add_extension(x509.KeyUsage(
                       digital_signature=True, content_commitment=False,
                       key_encipherment=False, data_encipherment=False,
                       key_agreement=False, key_cert_sign=True, crl_sign=True,
                       encipher_only=False, decipher_only=False), critical=True)
                   .sign(self.ca_key, hashes.SHA256()))

        self.leaf_key = ec.generate_private_key(ec.SECP256R1())
        self.leaf = (x509.CertificateBuilder()
                     .subject_name(x509.Name(
                         [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
                     .issuer_name(self.ca.subject)
                     .public_key(self.leaf_key.public_key())
                     .serial_number(x509.random_serial_number())
                     .not_valid_before(now - datetime.timedelta(days=1))
                     .not_valid_after(now + datetime.timedelta(days=365))
                     .add_extension(x509.BasicConstraints(ca=False,
                                                          path_length=None),
                                    critical=True)
                     .add_extension(x509.KeyUsage(
                         digital_signature=True, content_commitment=False,
                         key_encipherment=False, data_encipherment=False,
                         key_agreement=False, key_cert_sign=False,
                         crl_sign=False, encipher_only=False,
                         decipher_only=False), critical=True)
                     .add_extension(x509.ExtendedKeyUsage(
                         [ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                     .add_extension(x509.SubjectAlternativeName(
                         [x509.DNSName("localhost")]), critical=False)
                     .sign(self.ca_key, hashes.SHA256()))

        self.chain = [self.leaf.public_bytes(DER), self.ca.public_bytes(DER)]
        self.ours = allcrypt.EcKey.from_private(
            "P-256",
            self.leaf_key.private_numbers().private_value.to_bytes(32, "big"))
        self.ca_pem = self.ca.public_bytes(PEM).decode()

        self.identity = tmp_path / "server.pem"
        self.identity.write_bytes(
            self.leaf.public_bytes(PEM) + self.ca.public_bytes(PEM)
            + self.leaf_key.private_bytes(
                PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        self.ca_path = tmp_path / "ca.pem"
        self.ca_path.write_text(self.ca_pem)

    def response(self, status=ocsp.OCSPCertStatus.GOOD, revoked_at=None,
                 subject=None, this_update=None, next_update=None):
        """An OCSP response about the leaf, signed by the CA itself.

        Signed by the CA rather than a delegated responder because that
        is the simpler of the two legal shapes (RFC 6960 4.2.2.2) and the
        one a server operator most often has.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = ocsp.OCSPResponseBuilder().add_response(
            cert=subject or self.leaf, issuer=self.ca,
            algorithm=hashes.SHA1(),
            cert_status=status,
            this_update=this_update or (now - datetime.timedelta(hours=1)),
            next_update=next_update or (now + datetime.timedelta(days=1)),
            revocation_time=revoked_at,
            revocation_reason=(x509.ReasonFlags.key_compromise
                               if status == ocsp.OCSPCertStatus.REVOKED else None),
        ).responder_id(ocsp.OCSPResponderEncoding.NAME, self.ca)
        return builder.sign(self.ca_key, hashes.SHA256()).public_bytes(DER)

    def roots(self):
        store = allcrypt.TrustStore()
        store.add_pem(self.ca_pem)
        return store


@pytest.fixture
def pki(tmp_path):
    return Pki(tmp_path)


# ------------------------------------------- our server, OpenSSL's client ---

class OurServer:
    """An OpenSSL client and our server over memory BIOs."""

    def __init__(self, pki, *, version=TLS13, **options):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = version
        context.maximum_version = version
        context.load_verify_locations(cadata=pki.ca_pem)
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.client = context.wrap_bio(self.incoming, self.outgoing,
                                       server_hostname="localhost")
        name = {TLS12: "TLSv1.2", TLS13: "TLSv1.3"}[version]
        options.setdefault("now", NOW)
        options.setdefault("min_version", name)
        options.setdefault("max_version", name)
        self.server = allcrypt.TlsServer(pki.chain, pki.ours, **options)
        self.client_error = None
        self.server_error = None

    def pump(self, rounds=20):
        for _ in range(rounds):
            try:
                self.client.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            except ssl.SSLError as reason:
                self.client_error = reason
            data = self.outgoing.read()
            if data:
                self.server.push_incoming(data)
            try:
                self.server.process()
            except ValueError as reason:
                self.server_error = reason
                break
            out = self.server.take_outgoing()
            if out:
                self.incoming.write(out)
            if self.client_error:
                break
            if self.server.established and not out and not data:
                break
        return self


@pytest.mark.parametrize("version", [TLS12, TLS13])
def test_a_staple_does_not_break_an_openssl_client(pki, version):
    """The first thing to get right: an OpenSSL client that did **not**
    ask still completes the handshake.

    A server that stapled unasked would be sending a ServerHello
    extension, or a certificate-entry extension, that RFC 8446 4.2
    requires the client to refuse. Python's `ssl` does not request a
    staple, so this is exactly that case - and it passing means nothing
    was sent.
    """
    run = OurServer(pki, version=version,
                    ocsp_response=pki.response()).pump()
    assert run.server_error is None, run.server_error
    assert run.client_error is None, run.client_error
    assert run.server.established


# ------------------------------------------- our server, the openssl tool ---

def openssl():
    path = shutil.which("openssl")
    if path is None:
        pytest.skip("openssl is not installed")
    return path


class SocketServer:
    """Our server behind a real socket, for the `openssl` command line."""

    def __init__(self, pki, **options):
        self.pki = pki
        self.options = dict(now=NOW, min_version="TLSv1.2",
                            max_version="TLSv1.3")
        self.options.update(options)
        self.errors = []
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop.set()
        try:
            self.listener.close()
        except OSError:
            pass

    def _serve(self):
        while not self.stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(raw,),
                             daemon=True).start()

    def _handle(self, raw):
        connection = allcrypt.TlsServer(self.pki.chain, self.pki.ours,
                                        **self.options)
        raw.settimeout(5)
        try:
            while not connection.established:
                chunk = raw.recv(16384)
                if not chunk:
                    break
                connection.push_incoming(chunk)
                connection.process()
                out = connection.take_outgoing()
                if out:
                    raw.sendall(out)
            if connection.established:
                connection.write(b"HTTP/1.0 200 OK\r\n\r\nstapled")
                raw.sendall(connection.take_outgoing())
                time.sleep(0.2)
        except Exception as reason:                       # noqa: BLE001
            self.errors.append(reason)
        finally:
            try:
                raw.close()
            except OSError:
                pass


def s_client(port, ca_path, version):
    flag = {TLS12: "-tls1_2", TLS13: "-tls1_3"}[version]
    result = subprocess.run(
        [openssl(), "s_client", "-connect", f"127.0.0.1:{port}",
         "-servername", "localhost", "-CAfile", str(ca_path), flag,
         "-status", "-ign_eof"],
        input=b"", capture_output=True, timeout=20)
    return (result.stdout + result.stderr).decode(errors="replace")


@pytest.mark.parametrize("version", [TLS12, TLS13])
def test_the_openssl_tool_reads_our_staple(pki, version):
    """The one that matters for our server.

    `s_client -status` asks for a staple and prints what it got: OpenSSL
    parsed our extension - the 1.2 one in the ServerHello with the
    response in its own message, or the 1.3 one on the certificate entry
    - and then parsed the OCSP response inside it.

    Nothing on our side of the wire can say that. Our own client reads
    the extension with the same code that wrote it.
    """
    with SocketServer(pki, ocsp_response=pki.response()) as server:
        output = s_client(server.port, pki.ca_path, version)
    assert not server.errors, server.errors
    assert "OCSP Response Status: successful" in output, output[-3000:]
    assert "Cert Status: good" in output, output[-3000:]


@pytest.mark.parametrize("version", [TLS12, TLS13])
def test_a_server_with_nothing_to_staple_says_nothing(pki, version):
    """And the client is told so in as many words.

    `no response sent` is OpenSSL's way of saying the extension never
    came back, which is the correct behaviour rather than a failure: a
    server with no cached response simply does not answer the request.
    """
    with SocketServer(pki) as server:
        output = s_client(server.port, pki.ca_path, version)
    assert not server.errors, server.errors
    assert "no response sent" in output, output[-3000:]


# ------------------------------------------- our client, OpenSSL's server ---

def has_status_file():
    help_text = subprocess.run([openssl(), "s_server", "-help"],
                               capture_output=True, text=True).stderr
    return "-status_file" in help_text


class OpensslServer:
    """`openssl s_server` stapling a response from a file."""

    def __init__(self, tmp_path, pki, response=None, count=1, version=TLS13):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        self.port = listener.getsockname()[1]
        listener.close()

        command = [openssl(), "s_server", "-accept", str(self.port),
                   "-cert", str(pki.identity), "-naccept", str(count),
                   {TLS12: "-tls1_2", TLS13: "-tls1_3"}[version]]
        if response is not None:
            path = tmp_path / "staple.der"
            path.write_bytes(response)
            command += ["-status_file", str(path)]
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
        self._output = []
        listening = threading.Event()

        def drain(stream):
            for line in iter(stream.readline, b""):
                self._output.append(line)
                if line.startswith(b"ACCEPT"):
                    listening.set()
            stream.close()

        for stream in (self.process.stdout, self.process.stderr):
            threading.Thread(target=drain, args=(stream,), daemon=True).start()
        if not listening.wait(timeout=10):
            self.close()
            raise AssertionError("s_server never started listening: "
                                 + b"".join(self._output).decode())

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()


def run_client(port, pki, **options):
    """One `allcrypt.TlsClient` connection over a real socket."""
    options.setdefault("now", NOW)
    client = allcrypt.TlsClient("localhost", pki.roots(), **options)
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    raw.settimeout(5)
    error = None
    try:
        raw.sendall(client.take_outgoing())
        deadline = time.time() + 5
        while not client.established and time.time() < deadline:
            chunk = raw.recv(16384)
            if not chunk:
                break
            client.push_incoming(chunk)
            try:
                client.process()
            except ValueError as reason:
                error = reason
                break
            out = client.take_outgoing()
            if out:
                raw.sendall(out)
    finally:
        raw.close()
    return client, error


@pytest.mark.parametrize("version", [TLS12, TLS13])
def test_we_read_a_staple_from_the_openssl_tool(tmp_path, pki, version):
    """The one that matters for our client.

    `s_server -status_file` puts the response on the wire in whichever
    shape the negotiated version calls for, and our client has to find it
    in a different message in each. Our own server would put it wherever
    our client looked.
    """
    if not has_status_file():
        pytest.skip("this openssl s_server has no -status_file")
    response = pki.response()
    server = OpensslServer(tmp_path, pki, response,
                           version=version)
    try:
        client, error = run_client(
            server.port, pki,
            min_version={TLS12: "TLSv1.2", TLS13: "TLSv1.3"}[version],
            max_version={TLS12: "TLSv1.2", TLS13: "TLSv1.3"}[version])
    finally:
        server.close()
    assert error is None, error
    assert client.established
    assert client.stapled_ocsp == response


@pytest.mark.parametrize("version", [TLS12, TLS13])
def test_a_server_that_staples_nothing_leaves_us_connected(tmp_path, pki,
                                                           version):
    """`None` is the ordinary case, not a failure.

    Most servers staple nothing, so a client that hard-failed here would
    refuse most of the web. What it must *not* do is report something.
    """
    server = OpensslServer(tmp_path, pki, None, version=version)
    try:
        client, error = run_client(
            server.port, pki,
            min_version={TLS12: "TLSv1.2", TLS13: "TLSv1.3"}[version],
            max_version={TLS12: "TLSv1.2", TLS13: "TLSv1.3"}[version])
    finally:
        server.close()
    assert error is None, error
    assert client.established
    assert client.stapled_ocsp is None


def test_a_client_that_did_not_ask_gets_nothing(tmp_path, pki):
    """`request_stapled_ocsp=False` means the extension never goes out,
    so a stapling server has nothing to answer."""
    if not has_status_file():
        pytest.skip("this openssl s_server has no -status_file")
    server = OpensslServer(tmp_path, pki, pki.response())
    try:
        client, error = run_client(server.port, pki,
                                   min_version="TLSv1.3",
                                   max_version="TLSv1.3",
                                   request_stapled_ocsp=False)
    finally:
        server.close()
    assert error is None, error
    assert client.established
    assert client.stapled_ocsp is None


# ------------------------------------- what a staple is allowed to decide ---

def test_a_revoked_staple_fails_the_handshake(tmp_path, pki):
    """**Whatever the policy says.**

    Being on a list is an answer; being off one is a claim about
    coverage. A client that treated a signed revocation as advice would
    have made the asymmetry meaningless, and `require_revocation`
    deliberately does not gate this one.
    """
    if not has_status_file():
        pytest.skip("this openssl s_server has no -status_file")
    revoked = pki.response(
        status=ocsp.OCSPCertStatus.REVOKED,
        revoked_at=datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(hours=2))
    server = OpensslServer(tmp_path, pki, revoked)
    try:
        client, error = run_client(server.port, pki,
                                   min_version="TLSv1.3",
                                   max_version="TLSv1.3")
    finally:
        server.close()
    assert error is not None, "a revoked certificate was accepted"
    assert "revoked" in str(error).lower()
    assert not client.established


def test_no_staple_with_require_stapled_ocsp_is_refused(tmp_path, pki):
    """`Unknown` is not `NotRevoked`.

    Off by default - most servers staple nothing - but a caller that
    turns it on is asking for the hard-fail, and no answer has to count
    as no answer or the setting means nothing.
    """
    server = OpensslServer(tmp_path, pki, None)
    try:
        client, error = run_client(server.port, pki,
                                   min_version="TLSv1.3",
                                   max_version="TLSv1.3",
                                   require_stapled_ocsp=True)
    finally:
        server.close()
    assert error is not None
    assert "requires one" in str(error).lower()
    assert not client.established


def test_a_staple_about_another_certificate_settles_nothing(tmp_path, pki):
    """A signed response is not an answer about *this* certificate.

    The responder may return several, and a `CertID` that matches
    nothing looks exactly like "the responder does not know this one".
    Under `require_revocation` that is a refusal; without it, it is
    simply not an answer - and either way it must not read as "good".
    """
    if not has_status_file():
        pytest.skip("this openssl s_server has no -status_file")
    # A perfectly valid response, signed by the same CA, about the CA.
    about_the_ca = pki.response(subject=pki.ca)
    server = OpensslServer(tmp_path, pki, about_the_ca, count=2)
    try:
        client, error = run_client(server.port, pki, min_version="TLSv1.3",
                                   max_version="TLSv1.3")
        assert error is None, error
        assert client.established, "without the policy it is not an error"

        strict, error = run_client(server.port, pki, min_version="TLSv1.3",
                                   max_version="TLSv1.3",
                                   require_stapled_ocsp=True)
    finally:
        server.close()
    assert error is not None
    assert not strict.established


def test_a_revoked_staple_fails_with_the_issuer_in_the_chain(pki):
    """The other half of finding the issuer.

    The test above has the leaf alone on the wire and the CA in the
    trust store; this one has the CA **in the chain**, which is a
    different branch and the one that would still work if the trust
    store lookup were removed. Without both, removing either goes
    unnoticed.

    Our server and our client on the wire, deliberately: what is being
    checked here is which certificate the response is matched against,
    and the response itself was built by python-cryptography.
    """
    revoked = pki.response(
        status=ocsp.OCSPCertStatus.REVOKED,
        revoked_at=datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(hours=2))
    # An empty trust store for the *staple*'s issuer lookup would still
    # find the CA, so the chain is what has to carry it - which it does:
    # `pki.chain` is [leaf, CA].
    with SocketServer(pki, ocsp_response=revoked,
                      min_version="TLSv1.3", max_version="TLSv1.3") as server:
        client, error = run_client(server.port, pki, min_version="TLSv1.3",
                                   max_version="TLSv1.3")
    assert error is not None, "a revoked certificate was accepted"
    assert "revoked" in str(error).lower()
    assert not client.established


def test_a_good_staple_with_the_issuer_in_the_chain_connects(pki):
    """The same path, and the answer that is not a refusal.

    Worth its own row: a `check_staple` that failed everything would
    pass the test above and fail here, and a sweep cannot tell the two
    apart from one direction.
    """
    with SocketServer(pki, ocsp_response=pki.response(),
                      min_version="TLSv1.3", max_version="TLSv1.3") as server:
        client, error = run_client(server.port, pki, min_version="TLSv1.3",
                                   max_version="TLSv1.3",
                                   require_stapled_ocsp=True)
    assert error is None, error
    assert client.established
    assert client.stapled_ocsp is not None
