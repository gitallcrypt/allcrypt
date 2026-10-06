"""The OpenSSL shim, driving real `curl` and `wget`.

`LD_PRELOAD=libssl.so curl https://old-box/` replaces OpenSSL's TLS with
this library's, underneath a program that knows nothing about it. These
tests run the real binaries against real OpenSSL origin servers on
loopback and check they come back with the page.

**The trap this file is written against.** A shim that fails to load
leaves the program working perfectly - against the real OpenSSL. Every
assertion about the connection still passes, and the test proves
nothing at all. So every test here also asserts that *we* were in the
path, through the `ALLCRYPT_LOG` file the shim writes. Without that
check the whole file is decoration.

The second thing worth stating: the point is not that `curl` still
works. It is that `curl` works against origins it otherwise **refuses**
- TLS 1.0, RSA key transport, CBC suites, 1024 bit keys - so each of
those has a companion test showing the unshimmed tool failing on the
same server.

Everything is on 127.0.0.1; nothing here touches the network. See the
note at the top of `conftest.py`.
"""

import datetime
import os
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


ROOT = pathlib.Path(__file__).resolve().parent.parent


def shim():
    """The built `libssl.so`.

    Fails rather than skips when it is missing, for the same reason as
    the proxy's binary: a test that quietly vanishes because somebody
    forgot to build is a hole that looks like a pass.
    """
    for candidate in [ROOT / "target" / "release" / "libssl.so",
                      ROOT / "target" / "debug" / "libssl.so"]:
        if candidate.exists():
            return str(candidate)
    pytest.fail("the shim is not built. Run `cargo build --release`.",
                pytrace=False)


def tool(name):
    path = shutil_which(name)
    if path is None:
        pytest.skip(f"{name} is not installed")
    return path


def shutil_which(name):
    import shutil
    return shutil.which(name)


# ------------------------------------------------------------- the origin ---

def make_identity(kind="rsa", common_name="localhost", days_valid=365,
                  days_ago=1, bits=2048):
    key = (rsa.generate_private_key(public_exponent=65537, key_size=bits)
           if kind == "rsa" else ec.generate_private_key(ec.SECP256R1()))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(1)
                   .not_valid_before(now - datetime.timedelta(days=days_ago))
                   .not_valid_after(now + datetime.timedelta(days=days_valid))
                   .add_extension(x509.BasicConstraints(ca=True,
                                                        path_length=None),
                                  critical=True)
                   .add_extension(
                       x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                       critical=False)
                   .add_extension(
                       x509.SubjectAlternativeName([x509.DNSName(common_name)]),
                       critical=False)
                   .sign(key, hashes.SHA256()))
    return key, certificate


class Origin:
    """A real OpenSSL HTTPS server on 127.0.0.1.

    The standard library's, deliberately: the far end has to be
    something this library did not write.
    """

    def __init__(self, *, identity=None, ciphers=None, version=None,
                 body=b"reached the old box"):
        self.key, self.certificate = identity or make_identity()
        self.pem = self.certificate.public_bytes(
            serialization.Encoding.PEM).decode()
        self.body = body

        handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
        handle.write(self.pem)
        handle.write(self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()).decode())
        handle.close()
        self._identity_path = handle.name

        roots = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
        roots.write(self.pem)
        roots.close()
        self.ca_path = roots.name

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Ciphers before the certificate: @SECLEVEL=0 is what lets a
        # weak suite or an old version be used at all, and
        # load_cert_chain checks the key against the level set at the
        # time.
        if ciphers:
            context.set_ciphers(ciphers + ":@SECLEVEL=0")
        context.load_cert_chain(self._identity_path)
        if version:
            context.minimum_version = version
            context.maximum_version = version
        self._context = context

        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self.port = self._listener.getsockname()[1]
        self.url = f"https://localhost:{self.port}/"
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
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                raw.close()
            except OSError:
                pass

    def close(self):
        self._stop = True
        for path in (self._identity_path, self.ca_path):
            try:
                os.unlink(path)
            except OSError:
                pass
        try:
            self._listener.close()
        except OSError:
            pass


# --------------------------------------------------------------- the runs ---

class Run:
    """What happened when a tool was run."""

    def __init__(self, completed, log):
        self.completed = completed
        self.log = log

    @property
    def ok(self):
        return self.completed.returncode == 0

    @property
    def body(self):
        return self.completed.stdout

    @property
    def message(self):
        return self.completed.stderr.decode("utf-8", "replace")

    @property
    def used_the_shim(self):
        """**The check without which none of this means anything.**

        A shim that did not load leaves the tool working against the
        real OpenSSL, and every assertion about the page still passes.
        The log file is the only evidence.
        """
        return "shim active" in self.log

    def negotiated(self):
        """The `host version suite [verdict]` line the shim logged."""
        for line in self.log.splitlines():
            if line.startswith("localhost "):
                return line
        return ""

    @property
    def libcrypto(self):
        """Where the shim found libcrypto, as it logged it.

        The other unobservable thing in this file. The shim looks its
        eighteen libcrypto functions up with `dlsym` rather than
        linking them, and it looks first in the *global* scope -
        `dlopen(NULL, ..)`, which under LD_PRELOAD is the libcrypto
        the program itself already loaded. Falling back to opening a
        copy by soname would put two libcryptos in the process, and
        the objects we build with one would be read by accessors from
        the other.

        Nothing about a successful connection distinguishes the two,
        so this line is the only evidence, exactly as `shim active` is
        the only evidence the shim loaded at all.
        """
        for line in self.log.splitlines():
            if line.startswith("libcrypto: "):
                return line[len("libcrypto: "):]
        return ""


def run(command, *, with_shim=True, environment=None, timeout=60):
    log = tempfile.NamedTemporaryFile(suffix=".log", delete=False)
    log.close()
    env = dict(os.environ)
    env["ALLCRYPT_QUIET"] = "1"
    if with_shim:
        env["LD_PRELOAD"] = shim()
        env["ALLCRYPT_LOG"] = log.name
    env.update(environment or {})
    try:
        completed = subprocess.run(command, capture_output=True, env=env,
                                   timeout=timeout)
        with open(log.name) as handle:
            return Run(completed, handle.read())
    finally:
        try:
            os.unlink(log.name)
        except OSError:
            pass


def curl(origin, *extra, **kwargs):
    return run([tool("curl"), "-sS", "--cacert", origin.ca_path, *extra,
                origin.url], **kwargs)


def wget(origin, *extra, **kwargs):
    return run([tool("wget"), "-q", "-O", "-", "--ca-certificate",
                origin.ca_path, *extra, origin.url], **kwargs)


@pytest.fixture
def origin():
    server = Origin()
    yield server
    server.close()


# -------------------------------------------------------------- the point ---

def test_curl_fetches_a_page_through_the_shim(origin):
    """The whole stack, under a program that knows nothing about it.

    Our record layer, key schedule, certificate verification and bignum,
    reached through `libcurl`'s own `SSL_connect`.
    """
    result = curl(origin)
    assert result.used_the_shim, "the shim did not load; this tested OpenSSL"
    assert result.ok, result.message
    assert result.body == b"reached the old box"


def test_wget_fetches_a_page_through_the_shim(origin):
    """`wget` takes the other path through the shim entirely: it hands
    over a file descriptor where `libcurl` hands over a pair of BIOs. A
    shim that implemented only one works perfectly with one tool and not
    at all with the other."""
    result = wget(origin)
    assert result.used_the_shim, "the shim did not load; this tested OpenSSL"
    assert result.ok, result.message
    assert result.body == b"reached the old box"


@pytest.mark.parametrize("fetch", [curl, wget], ids=["curl", "wget"])
def test_libcrypto_is_the_programs_own_and_not_a_second_copy(origin, fetch):
    """The shim must bind to the libcrypto already in the process.

    It hands back genuine `X509 *` objects, and the program then calls
    `X509_get_subject_name` and its relatives on them - from whichever
    libcrypto the program itself imports. If the shim resolved its own
    functions out of a *different* libcrypto, those two would be the
    same symbol names over different struct layouts and different
    allocators, and the crash would be inside OpenSSL on a pointer it
    had every reason to trust.

    Nothing about the fetch below distinguishes the two cases: both
    curl and wget were built against the same OpenSSL as is installed
    here, so a second copy would be byte-identical and the page would
    come back either way. The log line is the only evidence, which is
    why it is logged.

    Both tools, because they reach libcrypto differently - wget over a
    file descriptor, curl over a pair of BIOs that are themselves
    libcrypto objects.
    """
    result = fetch(origin)
    assert result.used_the_shim, "the shim did not load; this tested OpenSSL"
    assert result.ok, result.message
    assert result.libcrypto == "global scope", (
        "the shim did not use the program's own libcrypto but "
        f"{result.libcrypto!r} - see shim/src/objects.rs")


def test_the_certificate_is_actually_verified(origin):
    """Not merely "the handshake completed": the chain was checked, and
    the shim says so."""
    result = curl(origin)
    assert result.used_the_shim
    assert "[verified]" in result.negotiated(), result.log


def test_a_certificate_from_nowhere_is_refused(origin):
    """And the verification is real. Same server, a CA that did not
    issue it - `curl` must fail, because the shim reports the failure
    through `SSL_get_verify_result` and `curl` acts on it."""
    _, other = make_identity(common_name="somebody-else")
    handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    handle.write(other.public_bytes(serialization.Encoding.PEM).decode())
    handle.close()
    try:
        result = run([tool("curl"), "-sS", "--cacert", handle.name, origin.url])
        assert result.used_the_shim
        assert not result.ok, "curl accepted a certificate from an unknown CA"
    finally:
        os.unlink(handle.name)


def test_the_shim_refuses_as_well_as_reporting(origin):
    """The shim's *own* refusal, which nothing else would notice.

    `curl` and `wget` read `SSL_get_verify_result` and fail on their
    own, so the shim ending the handshake changes nothing they do -
    which makes it a check with nothing watching it, and one that could
    be removed without a single test noticing. Found exactly that way.

    It is worth keeping: a program that forgets to read the result
    would otherwise get a connection to an unverified server while
    having asked for a verified one. So the refusal is logged, and this
    reads the log.
    """
    _, other = make_identity(common_name="somebody-else")
    handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    handle.write(other.public_bytes(serialization.Encoding.PEM).decode())
    handle.close()
    try:
        result = run([tool("curl"), "-sS", "--cacert", handle.name, origin.url])
        assert result.used_the_shim
        assert not result.ok
        assert "refused: certificate verification failed" in result.log, \
            result.log
    finally:
        os.unlink(handle.name)


def test_insecure_means_insecure(origin):
    """`curl -k` turns verification off, and that decision stays with
    `curl`.

    The shim checks either way and puts the answer where
    `SSL_get_verify_result` finds it; whether a bad answer ends the
    connection is the program's call. Overriding that in either
    direction would be the shim deciding something it was not asked to.
    """
    _, other = make_identity(common_name="somebody-else")
    handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    handle.write(other.public_bytes(serialization.Encoding.PEM).decode())
    handle.close()
    try:
        result = run([tool("curl"), "-sS", "-k", "--cacert", handle.name,
                      origin.url])
        assert result.used_the_shim
        assert result.ok, result.message
        assert result.body == b"reached the old box"
        assert "[not verified]" in result.negotiated(), result.log
    finally:
        os.unlink(handle.name)


# -------------------------------------------- reaching what it exists for ---

# Each row says whether an unaided `curl` can reach that server, and
# the test checks the claim.
#
# **Both kinds of row are load bearing, and for different reasons.** A
# `refused` row is the shim earning its existence: the tool fails and
# the shim gets through. A `reachable` row is coverage - our
# implementation of that suite, exercised by a real tool - and proves
# nothing about necessity.
#
# Writing the expectation down rather than deriving it means a row that
# moves between the two categories fails loudly. It has already
# happened once: AES256-SHA over TLS 1.2 was written as a `refused` row
# on the assumption that a modern OpenSSL would decline SHA-1 CBC, and
# this distribution's does not. That assertion would otherwise have sat
# there passing for the wrong reason.
#
# The key type has to match the suite: `AES128-SHA` is RSA key
# transport and needs an RSA certificate, and an EC one makes the
# origin answer handshake_failure - which looks exactly like a broken
# client.
LEGACY = [
    # suite, version, key kind, does unaided curl refuse it?
    ("AES128-SHA", ssl.TLSVersion.TLSv1, "rsa", True),
    ("AES128-SHA", ssl.TLSVersion.TLSv1_1, "rsa", True),
    ("AES256-SHA", ssl.TLSVersion.TLSv1_2, "rsa", False),
    ("ECDHE-RSA-AES128-SHA", ssl.TLSVersion.TLSv1_2, "rsa", False),
    ("ECDHE-ECDSA-AES128-SHA", ssl.TLSVersion.TLSv1_2, "ec", False),
]


@pytest.mark.parametrize("suite,version,kind,refused_unaided", LEGACY)
def test_a_legacy_origin_is_reached_through_the_shim(suite, version, kind,
                                                     refused_unaided):
    """**The reason the shim exists**, for the rows marked refused.

    Two runs of the same command against the same server. The row says
    in advance whether the unaided tool can do it, and a row whose
    expectation no longer matches the tool fails here rather than
    quietly becoming decoration.
    """
    server = Origin(identity=make_identity(kind), ciphers=suite,
                    version=version)
    try:
        plain = curl(server, with_shim=False)
        if refused_unaided:
            assert not plain.ok, (
                f"curl reached a {suite} / {version.name} server unaided. The "
                f"row claims it cannot, so either the tool changed or the "
                f"expectation was wrong - and as written this row no longer "
                f"shows the shim is needed.")
        else:
            assert plain.ok, (
                f"curl could not reach a {suite} / {version.name} server "
                f"unaided, but the row says it can. Mark it refused=True and "
                f"it becomes evidence for the shim rather than coverage.")

        shimmed = curl(server)
        assert shimmed.used_the_shim
        assert shimmed.ok, shimmed.message
        assert shimmed.body == b"reached the old box"
    finally:
        server.close()


def test_some_row_actually_needs_the_shim():
    """A guard on the table above.

    Every row could drift to `refused=False` - a newer OpenSSL
    loosening, a distribution changing its security level - and each
    one would still pass, individually, while the file as a whole
    stopped demonstrating anything. This fails if none is left.
    """
    assert any(row[3] for row in LEGACY), (
        "no row in LEGACY is refused by an unaided curl any more, so nothing "
        "here shows the shim reaches something the tool cannot")


def test_wget_reaches_a_tls_1_0_origin():
    """The same, through the descriptor path rather than the BIO one."""
    server = Origin(identity=make_identity("rsa"), ciphers="AES128-SHA",
                    version=ssl.TLSVersion.TLSv1)
    try:
        plain = wget(server, with_shim=False)
        assert not plain.ok, "wget reached a TLS 1.0 server unaided"

        shimmed = wget(server)
        assert shimmed.used_the_shim
        assert shimmed.ok, shimmed.message
        assert shimmed.body == b"reached the old box"
    finally:
        server.close()


def test_a_1024_bit_key_is_reached():
    """A key nobody would issue today, on a box nobody will reissue for."""
    server = Origin(identity=make_identity("rsa", bits=1024),
                    ciphers="AES128-SHA", version=ssl.TLSVersion.TLSv1_2)
    try:
        plain = curl(server, with_shim=False)
        assert not plain.ok, "curl accepted a 1024 bit key unaided"

        shimmed = curl(server)
        assert shimmed.used_the_shim
        assert shimmed.ok, shimmed.message
    finally:
        server.close()


def test_the_version_negotiated_is_the_old_one():
    """Not just "it worked": the connection really was TLS 1.0, rather
    than the origin quietly accepting something newer."""
    server = Origin(identity=make_identity("rsa"), ciphers="AES128-SHA",
                    version=ssl.TLSVersion.TLSv1)
    try:
        result = curl(server)
        assert result.used_the_shim
        assert result.ok, result.message
        line = result.negotiated()
        assert " TLSv1 " in line, line
        assert "TLS_RSA_WITH_AES_128_CBC_SHA" in line, line
    finally:
        server.close()


# ------------------------------------------------------- what it will not do ---

def test_the_shim_is_permissive_but_can_be_tightened(origin):
    """`ALLCRYPT_CIPHERS` is the way back to a narrow offer, and it
    really narrows: a modern-only client cannot reach a TLS 1.0 box."""
    server = Origin(identity=make_identity("rsa"), ciphers="AES128-SHA",
                    version=ssl.TLSVersion.TLSv1)
    try:
        wide = curl(server)
        assert wide.ok, wide.message

        narrow = curl(server, environment={"ALLCRYPT_CIPHERS": "modern",
                                           "ALLCRYPT_MIN_VERSION": "TLSv1.2"})
        assert narrow.used_the_shim
        assert not narrow.ok, "ALLCRYPT_CIPHERS=modern still reached TLS 1.0"
    finally:
        server.close()


def test_a_client_certificate_is_refused_rather_than_skipped(origin):
    """**Refusing loudly beats ignoring quietly.**

    The shim cannot present a client certificate. If it accepted the
    request and connected without one, the program would report success
    for an authentication that did not happen - and against a server
    that merely *requests* rather than requires one, it would look
    entirely fine.
    """
    key, certificate = make_identity("rsa")
    handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    handle.write(certificate.public_bytes(serialization.Encoding.PEM).decode())
    handle.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode())
    handle.close()
    try:
        result = curl(origin, "--cert", handle.name)
        assert result.used_the_shim
        assert not result.ok, (
            "the shim connected without the client certificate it was asked "
            "to present")
        # **Why** it failed matters. Without this the test passed on any
        # refusal anywhere in the shim - it did, on
        # `SSL_CTX_check_private_key` returning 0.
        #
        # Two independent things refuse here and either alone is
        # enough, so breaking one still leaves this passing. That is
        # defence in depth doing its job rather than a hole, but it
        # does mean the breakage sweep cannot isolate them; the
        # comment on `SSL_CTX_check_private_key` says so at the code.
        assert "client certificate" in result.log, result.log
    finally:
        os.unlink(handle.name)


def test_a_revocation_list_is_refused_rather_than_ignored():
    """`wget --crl-file` reaches `X509_load_crl_file`, which this shim
    does not honour. It says so and fails, rather than letting wget
    report success for a revocation check that never happened."""
    server = Origin()
    handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    handle.write("")
    handle.close()
    try:
        result = wget(server, "--crl-file", handle.name)
        assert result.used_the_shim
        assert not result.ok, (
            "wget reported success with a CRL file the shim ignored")
    finally:
        os.unlink(handle.name)
        server.close()


def test_the_shim_says_it_is_there(origin):
    """A program whose TLS stack was swapped underneath it should say
    so somewhere. Without it, somebody debugs a connection for an hour
    with the wrong library's documentation open."""
    env = dict(os.environ)
    env["LD_PRELOAD"] = shim()
    completed = subprocess.run(
        [tool("curl"), "-sS", "--cacert", origin.ca_path, origin.url],
        capture_output=True, env=env, timeout=60)
    assert completed.returncode == 0, completed.stderr
    assert b"allcrypt" in completed.stderr
    assert b"not OpenSSL" in completed.stderr


def test_quiet_means_quiet(origin):
    """Because the banner lands in the middle of another program's
    output, and some of those outputs are parsed."""
    result = curl(origin)
    assert result.used_the_shim
    assert b"allcrypt" not in result.completed.stderr, result.message
