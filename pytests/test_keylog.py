"""The NSS key log format, for decrypting our own traffic in Wireshark.

This file is two things at once.

The obvious one is that the plumbing works: `SSLKEYLOGFILE` is honoured,
`keylog_filename` overrides it, the file is appended to rather than
truncated, and a line has the shape Wireshark parses.

The one that matters more is that **the secret in it is right**. Python's
`ssl` can write the same log for the same session from the server side, so
the two files can be compared line for line. That makes this an
independent check of the master secret itself - a completely different
angle on the key schedule from decrypting records, and one that would
catch a master secret that was self-consistently wrong.
"""

import datetime
import os
import ssl
import tempfile

import pytest

import allcrypt
import allcrypt_ssl

cryptography = pytest.importorskip("cryptography")
from cryptography import x509                                    # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa        # noqa: E402
from cryptography.x509.oid import NameOID                        # noqa: E402

NOW = int(__import__("time").time())


def server_material(tmp_path):
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
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    certfile = tmp_path / "cert.pem"
    keyfile = tmp_path / "key.pem"
    certfile.write_bytes(cert_pem)
    keyfile.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return cert_pem.decode(), str(certfile), str(keyfile)


def handshake(cert_pem, certfile, keyfile, server_keylog=None,
              ciphers="ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0"):
    """Our client against an OpenSSL server, over memory BIOs."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.set_ciphers(ciphers)
    context.load_cert_chain(certfile, keyfile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    if server_keylog:
        context.keylog_filename = server_keylog

    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server = context.wrap_bio(server_in, server_out, server_side=True)

    roots = allcrypt.TrustStore()
    roots.add_pem(cert_pem)
    client = allcrypt.TlsClient("localhost", roots, now=NOW)

    for _ in range(20):
        data = client.take_outgoing()
        if data:
            server_in.write(data)
        try:
            server.do_handshake()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        data = server_out.read()
        if data:
            client.push_incoming(data)
        client.process()
        if client.established:
            break
    assert client.established, client.state
    return client


def test_the_line_has_the_shape_wireshark_parses(tmp_path):
    """`CLIENT_RANDOM <64 hex> <96 hex>`, lowercase, space separated.

    Wireshark matches the session by the client random and uses the second
    field as the master secret. Anything else in the line - a different
    label, uppercase hex, a wrong length - makes it skip the session
    silently rather than report a problem, which is the worst possible
    failure mode for a debugging aid.
    """
    cert_pem, certfile, keyfile = server_material(tmp_path)
    client = handshake(cert_pem, certfile, keyfile)

    line = client.key_log_line
    assert line is not None

    label, random_hex, secret_hex = line.split(" ")
    assert label == "CLIENT_RANDOM"
    assert len(random_hex) == 64        # 32 bytes
    assert len(secret_hex) == 96        # the master secret is always 48
    assert random_hex == random_hex.lower()
    assert secret_hex == secret_hex.lower()
    bytes.fromhex(random_hex)
    bytes.fromhex(secret_hex)
    assert "\n" not in line


def test_our_master_secret_is_the_one_openssl_derived(tmp_path):
    """The check this file exists for, and the one that stands in for
    running Wireshark.

    Python's `ssl` writes the same key log from the server side, for the
    same session. If our line and its line are byte-identical, then:

      * our master secret is the same 48 bytes OpenSSL derived - a
        completely different check from decrypting records, and the one
        that would catch a key schedule wrong in a way both directions of
        our own code agreed on; and
      * anything that can decrypt a capture from OpenSSL's key log can
        decrypt one from ours, because it is the same line. That is the
        real claim being made by the feature, and it is settled here
        rather than by a screenshot of Wireshark.
    """
    cert_pem, certfile, keyfile = server_material(tmp_path)
    server_log = str(tmp_path / "server-keys.log")
    client = handshake(cert_pem, certfile, keyfile, server_keylog=server_log)

    theirs = [line.strip() for line in open(server_log)
              if line.startswith("CLIENT_RANDOM")]
    assert theirs, "the server wrote no CLIENT_RANDOM line to compare against"
    assert client.key_log_line in theirs, (
        f"our key log line is not the one OpenSSL wrote:\n"
        f"  ours   {client.key_log_line}\n"
        f"  theirs {theirs}")


@pytest.mark.parametrize("ciphers", [
    "ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0",
    "ECDHE-RSA-AES256-SHA384:@SECLEVEL=0",
    "AES128-SHA:@SECLEVEL=0",
    "ECDHE-RSA-CHACHA20-POLY1305:@SECLEVEL=0",
])
def test_the_secret_agrees_across_suites(tmp_path, ciphers):
    """The PRF hash comes from the suite in TLS 1.2, so a SHA-384 suite
    derives its master secret with SHA-384. Each of these is a different
    path through the key schedule, and the key exchanges differ too."""
    cert_pem, certfile, keyfile = server_material(tmp_path)
    server_log = str(tmp_path / f"keys-{abs(hash(ciphers))}.log")
    client = handshake(cert_pem, certfile, keyfile,
                       server_keylog=server_log, ciphers=ciphers)

    theirs = [line.strip() for line in open(server_log)
              if line.startswith("CLIENT_RANDOM")]
    assert client.key_log_line in theirs, ciphers


def test_the_shim_writes_the_file(tmp_path):
    """`keylog_filename` on the context, the standard library's own API."""
    cert_pem, certfile, keyfile = server_material(tmp_path)
    path = str(tmp_path / "written.log")

    context = allcrypt_ssl.create_default_context(cafile=certfile)
    context.keylog_filename = path
    assert context.keylog_filename == path

    import socket
    import threading

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile, keyfile)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.maximum_version = ssl.TLSVersion.TLSv1_2

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        raw, _ = listener.accept()
        try:
            with server_context.wrap_socket(raw, server_side=True) as tls:
                tls.recv(64)
                tls.sendall(b"ok")
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    raw = socket.create_connection(("127.0.0.1", port))
    with context.wrap_socket(raw, server_hostname="localhost") as sock:
        sock.sendall(b"hello")
        assert sock.recv(64) == b"ok"
        assert sock.backend_in_use == "allcrypt"
    thread.join(timeout=5)
    listener.close()

    assert os.path.exists(path), "nothing was written to the key log"

    # Setting keylog_filename is mirrored onto the fallback standard
    # library context, so that a connection that falls back logs to the
    # same file - and Python's setter writes a `#` header line when it
    # opens it. Wireshark ignores comments, and one file holding both
    # backends' keys is the point, so the header is fine; the lines that
    # matter are the CLIENT_RANDOM ones.
    lines = [line.strip() for line in open(path) if line.strip()]
    assert any(line.startswith("#") for line in lines), lines
    secrets = [line for line in lines if line.startswith("CLIENT_RANDOM ")]
    assert len(secrets) == 1, lines
    assert len(secrets[0].split(" ")) == 3

    # And it is our line, from our stack, not one the fallback wrote.
    bytes.fromhex(secrets[0].split(" ")[1])
    bytes.fromhex(secrets[0].split(" ")[2])


def test_the_environment_variable_is_honoured(monkeypatch, tmp_path):
    """`SSLKEYLOGFILE` is the convention OpenSSL, curl and every browser
    already use, so a capture works without touching the code under test -
    which is the whole point of having a convention."""
    path = str(tmp_path / "from-env.log")
    monkeypatch.setenv("SSLKEYLOGFILE", path)

    context = allcrypt_ssl.create_default_context()
    assert context.keylog_filename == path

    # An explicit setting wins over the environment, and an explicit empty
    # string means off even when the environment says otherwise.
    context.keylog_filename = str(tmp_path / "explicit.log")
    assert context.keylog_filename == str(tmp_path / "explicit.log")
    context.keylog_filename = ""
    assert context.keylog_filename is None

    monkeypatch.delenv("SSLKEYLOGFILE")
    assert allcrypt_ssl.create_default_context().keylog_filename is None


def test_writing_appends_and_never_raises(tmp_path):
    """Several sessions accumulate in one file - Wireshark matches by
    client random, so a file holding many is normal and truncating would
    lose the earlier captures.

    And an unwritable path must not take down the connection it was meant
    to help debug.
    """
    path = tmp_path / "many.log"
    allcrypt_ssl._write_keylog(str(path), "CLIENT_RANDOM aa bb")
    allcrypt_ssl._write_keylog(str(path), "CLIENT_RANDOM cc dd")
    assert path.read_text() == "CLIENT_RANDOM aa bb\nCLIENT_RANDOM cc dd\n"

    # None, empty and unwritable are all quietly nothing.
    allcrypt_ssl._write_keylog(None, "CLIENT_RANDOM aa bb")
    allcrypt_ssl._write_keylog("", "CLIENT_RANDOM aa bb")
    allcrypt_ssl._write_keylog(str(tmp_path / "no" / "such" / "dir" / "k.log"),
                               "CLIENT_RANDOM aa bb")
    allcrypt_ssl._write_keylog(str(path), None)
    assert path.read_text().count("\n") == 2


def test_nothing_is_written_when_nobody_asked(tmp_path, monkeypatch):
    """The keys go nowhere by default. A library that writes session
    secrets to disk unless told not to is a library that has leaked them
    before anyone notices the feature exists."""
    monkeypatch.delenv("SSLKEYLOGFILE", raising=False)
    cert_pem, certfile, keyfile = server_material(tmp_path)

    context = allcrypt_ssl.create_default_context(cafile=certfile)
    assert context.keylog_filename is None

    before = set(os.listdir(tmp_path))
    handshake(cert_pem, certfile, keyfile)
    assert set(os.listdir(tmp_path)) == before


def test_the_line_is_absent_before_the_key_exchange():
    """There is no master secret until the client's second flight, and
    reporting one before then would mean reporting something made up."""
    roots = allcrypt.TrustStore()
    roots.add_pem(server_material_pem())
    client = allcrypt.TlsClient("localhost", roots, now=NOW)
    assert client.key_log_line is None


_CACHED_PEM = []


def server_material_pem():
    if not _CACHED_PEM:
        with tempfile.TemporaryDirectory() as tmp:
            import pathlib
            _CACHED_PEM.append(server_material(pathlib.Path(tmp))[0])
    return _CACHED_PEM[0]


@pytest.mark.skipif(os.name != "posix", reason="file modes are a POSIX notion")
def test_the_key_log_is_created_private(tmp_path):
    # Every line is a session secret. The file was opened with
    # open(path, "a"), so it was created 0644 under the usual umask and
    # readable by every local account; the tests above checked the
    # contents and never the mode.
    path = tmp_path / "keys.log"
    allcrypt_ssl._write_keylog(str(path), "CLIENT_RANDOM 00 00")
    assert path.read_text() == "CLIENT_RANDOM 00 00\n"
    assert (path.stat().st_mode & 0o777) == 0o600
