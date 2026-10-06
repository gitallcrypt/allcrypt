"""Connecting with no hostname: no SNI, and no name to check.

Reported from another machine: `wrap_socket` refused
`server_hostname=None` even with `check_hostname = False` and
`CERT_NONE` set, so there was no way to talk to a box by address or to
something whose certificate was not going to be judged. Python's `ssl`
allows it — it simply sends no `server_name` extension — and this shim
did not.

Two things have to be true for the fix to be worth anything, and a
round trip against ourselves proves neither:

  * the rule must be **CPython's** rule, error message included, because
    a caller who hits it searches for that string;
  * the resulting ClientHello must be one a real server accepts, with
    the `server_name` extension **absent** rather than present and
    empty. RFC 6066 section 3 defines the body as a non-empty list, and
    the empty form gets an alert from some servers and the default
    certificate from others — which works until it does not.

So the handshake here runs against OpenSSL through `ssl`, and the hello
is parsed to check what is in it.
"""

import datetime
import socket
import ssl
import threading
import time

import pytest

import allcrypt
import allcrypt_ssl

cryptography = pytest.importorskip("cryptography")
from cryptography import x509                                     # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa         # noqa: E402
from cryptography.x509.oid import NameOID                         # noqa: E402

NOW = int(time.time())


def server_material(tmp_path):
    """A self-signed localhost certificate, and the files OpenSSL wants."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    certfile = tmp_path / "cert.pem"
    keyfile = tmp_path / "key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return str(certfile), str(keyfile)


# --------------------------------------------------------- the rule itself ---

def test_no_hostname_is_allowed_when_nothing_checks_it():
    """`check_hostname = False` and `CERT_NONE`: exactly what `ssl` does."""
    context = allcrypt_ssl.SSLContext(allcrypt_ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = allcrypt_ssl.CERT_NONE

    wrapped = context.wrap_socket(socket.socket(), server_hostname=None)
    assert context.backend_in_use == "allcrypt"
    assert wrapped.server_hostname is None

    # And through the memory-BIO path, which asyncio drives.
    obj = context.wrap_bio(allcrypt_ssl.MemoryBIO(), allcrypt_ssl.MemoryBIO(),
                           server_hostname=None)
    assert obj.server_hostname is None


def test_the_error_is_cpythons_error():
    """With `check_hostname` on it is still refused — and with the same
    words, because a caller who hits it searches for them."""
    ours = allcrypt_ssl.SSLContext(allcrypt_ssl.PROTOCOL_TLS_CLIENT)
    theirs = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    assert ours.check_hostname and theirs.check_hostname

    with pytest.raises(ValueError) as caught_ours:
        ours.wrap_socket(socket.socket(), server_hostname=None)
    with pytest.raises(ValueError) as caught_theirs:
        theirs.wrap_socket(socket.socket(), server_hostname=None)
    assert str(caught_ours.value) == str(caught_theirs.value)


def test_the_standard_library_agrees_this_is_allowed():
    """The claim this file rests on, asserted rather than assumed: `ssl`
    itself accepts `server_hostname=None` once nothing checks a name."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    wrapped = context.wrap_socket(socket.socket(), server_hostname=None)
    assert wrapped.server_hostname is None


# ------------------------------------------------------- what goes on the wire ---

def hello_extensions(record):
    """The extension types in a ClientHello record, parsed rather than
    scanned for.

    A byte scan would lie in both directions: 0x0000 is the
    `server_name` code and also appears inside a random, a session id
    and a key share.
    """
    body = record[5:]
    assert body[0] == 1, "not a ClientHello"
    at = 4 + 2 + 32                       # handshake header, version, random
    at += 1 + body[at]                    # legacy_session_id
    at += 2 + int.from_bytes(body[at:at + 2], "big")      # cipher suites
    at += 1 + body[at]                    # compression methods
    total = int.from_bytes(body[at:at + 2], "big")
    at += 2
    end = at + total

    kinds = []
    while at + 4 <= end:
        kind = int.from_bytes(body[at:at + 2], "big")
        length = int.from_bytes(body[at + 2:at + 4], "big")
        kinds.append(kind)
        at += 4 + length
    return kinds


SERVER_NAME = 0x0000
SIGNATURE_ALGORITHMS = 0x000d


def test_no_hostname_sends_no_server_name_extension():
    """**Absent, not present and empty.** An empty `server_name` body is
    malformed by RFC 6066 section 3, and the two ways servers react to it
    - an alert, or the default certificate - are both silent from here."""
    roots = allcrypt.TrustStore()
    roots.add_pem(_throwaway_root())

    nameless = allcrypt.TlsClient("", roots, now=NOW, verify=False,
                                  verify_hostname=False)
    kinds = hello_extensions(nameless.take_outgoing())
    assert SERVER_NAME not in kinds, "a server_name extension was sent"
    assert SIGNATURE_ALGORITHMS in kinds, "the rest of the hello went missing too"

    named = allcrypt.TlsClient("example.test", roots, now=NOW, verify=False)
    assert SERVER_NAME in hello_extensions(named.take_outgoing())


def test_a_hostname_is_still_required_while_the_name_is_checked():
    """At the Rust layer too, not only in the shim. Otherwise the shim is
    the only thing standing between a caller and a connection that
    silently checks nothing."""
    roots = allcrypt.TrustStore()
    roots.add_pem(_throwaway_root())
    with pytest.raises(allcrypt.CryptoError) as caught:
        allcrypt.TlsClient("", roots, now=NOW, verify=False)
    assert "verify_hostname" in str(caught.value)


def _throwaway_root():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "throwaway")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# --------------------------------------------- and a server actually accepts it ---

def serve_once(certfile, keyfile, maximum):
    """One OpenSSL connection on a loopback port, echoing what it reads."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    context.maximum_version = maximum

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    seen = {}

    def run():
        try:
            raw, _ = listener.accept()
            with context.wrap_socket(raw, server_side=True) as tls:
                seen["sni"] = tls.server_hostname
                data = tls.recv(4096)
                tls.sendall(b"saw:" + (data or b""))
        except Exception as problem:            # noqa: BLE001 - reported below
            seen["error"] = repr(problem)
        finally:
            listener.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return port, thread, seen


@pytest.mark.parametrize("maximum", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3],
                         ids=["tls12", "tls13"])
def test_a_real_server_completes_the_handshake_without_sni(tmp_path, maximum):
    """The check that matters. A hello our own code is happy with proves
    nothing about whether OpenSSL will take it."""
    certfile, keyfile = server_material(tmp_path)
    port, thread, seen = serve_once(certfile, keyfile, maximum)

    context = allcrypt_ssl.SSLContext(allcrypt_ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = allcrypt_ssl.CERT_NONE
    context.maximum_version = allcrypt_ssl.TLSVersion(maximum.value)

    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    with context.wrap_socket(raw, server_hostname=None) as tls:
        assert context.backend_in_use == "allcrypt", "fell back to the stdlib"
        tls.sendall(b"hello")
        assert tls.recv(4096) == b"saw:hello"
        assert tls.version() is not None

    thread.join(timeout=10)
    assert "error" not in seen, seen["error"]
    # The server saw no name, which is what "no SNI" means from the
    # other end - and is the only place that can say so.
    assert seen["sni"] is None


def test_wrapping_an_unconnected_socket_then_connecting(tmp_path):
    """`ssl` wraps an unconnected socket and waits for `connect`.

    This used to handshake immediately and die with `BrokenPipeError`,
    and `connect` fell through `__getattr__` to the raw socket - so it
    connected the TCP socket and never started a handshake, leaving the
    caller reading TLS records as though they were the reply.
    """
    certfile, keyfile = server_material(tmp_path)
    port, thread, seen = serve_once(certfile, keyfile, ssl.TLSVersion.TLSv1_3)

    context = allcrypt_ssl.SSLContext(allcrypt_ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = allcrypt_ssl.CERT_NONE

    tls = context.wrap_socket(socket.socket(), server_hostname=None)
    tls.connect(("127.0.0.1", port))
    try:
        tls.sendall(b"late")
        assert tls.recv(4096) == b"saw:late"
        # A second connect is a mistake, not a reconnect.
        with pytest.raises(ValueError):
            tls.connect(("127.0.0.1", port))
    finally:
        tls.close()

    thread.join(timeout=10)
    assert "error" not in seen, seen["error"]
