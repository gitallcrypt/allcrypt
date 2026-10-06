#!/usr/bin/env python3
"""The hybrid post-quantum TLS groups, against OpenSSL 3.5 on loopback.

`pytests/test_hybrid_kex.py` can only connect this library to itself
for the three RFC 10024 groups, because the OpenSSL the test suite runs
against is 3.0 and has never heard of them. Two copies of one
implementation agree about a share layout whichever way round it is, so
that settles the wiring and nothing about the layout.

OpenSSL 3.5 has all three. This script drives, for each group:

  * **our client against `openssl s_server`** pinned to that group - for
    X25519MLKEM768 the share we sent first, for the other two a
    HelloRetryRequest onto a hybrid group;
  * **`openssl s_client` against our server**, pinned the same way, so
    OpenSSL parses the share we answer with and checks the secret.

Each connection then carries application data both ways, because
matching Finished messages say the transcripts agree and only records
that decrypt say the secrets do.

    python3 scripts/check_pq_witness.py --openssl /opt/openssl35/bin/openssl

**A development tool, not a test.** It needs an OpenSSL 3.5 binary and
loopback sockets, and nothing in the test suite runs it; no test in this
repository uses the network. Its result is recorded in
`docs/post-quantum.md` with the OpenSSL version it was run against.
"""

import argparse
import datetime
import os
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "python"))

import allcrypt  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

GROUPS = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"]
MESSAGE = b"over a post-quantum key\n"


def identity(directory):
    """A self-signed P-256 certificate for localhost, as files for
    OpenSSL and as objects for us."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(1)
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=30))
                   .add_extension(x509.SubjectAlternativeName(
                       [x509.DNSName("localhost")]), critical=False)
                   .add_extension(x509.BasicConstraints(ca=True,
                                                        path_length=None),
                                  critical=True)
                   .sign(key, hashes.SHA256()))
    cert_path = os.path.join(directory, "cert.pem")
    key_path = os.path.join(directory, "key.pem")
    with open(cert_path, "wb") as out:
        out.write(certificate.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as out:
        out.write(key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    scalar = key.private_numbers().private_value.to_bytes(32, "big")
    return certificate, allcrypt.EcKey.from_private("P-256", scalar), \
        cert_path, key_path


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def pump(sock, connection, until, deadline):
    """Move bytes between a socket and a sans-I/O connection until
    `until()` holds."""
    sock.settimeout(0.2)
    while not until():
        if time.time() > deadline:
            raise TimeoutError("no progress")
        out = connection.take_outgoing()
        if out:
            sock.sendall(out)
        try:
            data = sock.recv(65536)
        except socket.timeout:
            continue
        if not data:
            raise ConnectionError("peer closed")
        connection.push_incoming(data)
        connection.process()


def our_client(openssl, group, files, certificate):
    """Our client, `openssl s_server -groups <group>`."""
    port = free_port()
    _, _, cert_path, key_path = files
    server = subprocess.Popen(
        [openssl, "s_server", "-accept", f"127.0.0.1:{port}", "-tls1_3",
         "-groups", group, "-cert", cert_path, "-key", key_path, "-rev",
         "-quiet"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=2)
                break
            except OSError:
                time.sleep(0.1)
        else:
            return False, "s_server did not start"
        roots = allcrypt.TrustStore()
        roots.add_pem(certificate.public_bytes(
            serialization.Encoding.PEM).decode())
        client = allcrypt.TlsClient("localhost", roots,
                                    now=int(time.time()),
                                    min_version="TLSv1.3",
                                    max_version="TLSv1.3")
        deadline = time.time() + 20
        with sock:
            pump(sock, client, lambda: client.established, deadline)
            # `-rev` answers each line reversed: a reply that decrypts
            # is a key both ends derived.
            client.write(MESSAGE)
            received = bytearray()
            def got_reply():
                received.extend(client.take_incoming())
                return b"\n" in received
            pump(sock, client, got_reply, deadline)
        expected = MESSAGE.rstrip(b"\n")[::-1]
        ok = (client.named_group == group and client.certificate_verified
              and expected in bytes(received))
        reply = "ok" if expected in bytes(received) else repr(bytes(received))
        return ok, f"group={client.named_group} reply={reply}"
    except Exception as error:  # noqa: BLE001 - reported, not hidden
        return False, f"{type(error).__name__}: {error}"
    finally:
        server.kill()
        server.wait()


def our_server(openssl, group, files, certificate):
    """`openssl s_client -groups <group>`, our server."""
    der = certificate.public_bytes(serialization.Encoding.DER)
    _, key, _, _ = files
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    client = subprocess.Popen(
        [openssl, "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3",
         "-groups", group, "-servername", "localhost", "-brief",
         "-ign_eof"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    try:
        listener.settimeout(10)
        sock, _ = listener.accept()
        server = allcrypt.TlsServer([der], key, now=int(time.time()),
                                    min_version="TLSv1.3")
        deadline = time.time() + 20
        with sock:
            pump(sock, server, lambda: server.established, deadline)
            client.stdin.write(MESSAGE)
            client.stdin.flush()
            received = bytearray()
            def got_line():
                received.extend(server.take_incoming())
                return b"\n" in received
            pump(sock, server, got_line, deadline)
            server.write(bytes(received)[::-1].lstrip(b"\n") + b"\n")
            sock.sendall(server.take_outgoing())
            time.sleep(0.5)
        client.stdin.close()
        output = client.stdout.read().decode(errors="replace")
        negotiated = ""
        for line in output.splitlines():
            if "group" in line.lower():
                negotiated = line.strip()
        echoed = MESSAGE.rstrip(b"\n")[::-1].decode() in output
        ok = bytes(received) == MESSAGE and echoed and group in negotiated
        return ok, (f"openssl says {negotiated!r} "
                    f"data={'ok' if echoed else 'missing'}")
    except Exception as error:  # noqa: BLE001
        return False, f"{type(error).__name__}: {error}"
    finally:
        listener.close()
        client.kill()
        client.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--openssl", default="openssl",
                        help="an OpenSSL 3.5 or later binary")
    args = parser.parse_args()
    # A witness built into its own prefix needs its own libraries found.
    lib = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(args.openssl))), "lib")
    if os.path.isdir(lib):
        os.environ["LD_LIBRARY_PATH"] = lib
    version = subprocess.run([args.openssl, "version"], capture_output=True,
                             text=True).stdout.strip()
    print(f"witness: {version}")
    failures = 0
    with tempfile.TemporaryDirectory() as directory:
        certificate, key, cert_path, key_path = identity(directory)
        files = (certificate, key, cert_path, key_path)
        for group in GROUPS:
            for label, run in (("our client ", our_client),
                               ("our server ", our_server)):
                ok, detail = run(args.openssl, group, files, certificate)
                failures += not ok
                print(f"  {'ok  ' if ok else 'FAIL'} {label}{group:20} {detail}")
    print(f"\n{2 * len(GROUPS) - failures} of {2 * len(GROUPS)} passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
