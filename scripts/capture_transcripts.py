#!/usr/bin/env python3
"""Capture real TLS handshakes into tests/transcripts/handshakes.json.

Both sides are Python's `ssl` in memory-BIO mode, pumped by hand - no
sockets, which is exactly the sans-I/O shape our own record layer has. The
result is every byte that crossed in each direction, for a handshake that
really happened between two implementations that are not ours.

This is the fixture the record layer and the handshake state machine are
developed against, before any live connection. A state machine bug is the
category unit tests are worst at catching; a recorded transcript is the
thing that catches it.

    python3 scripts/capture_transcripts.py

Rerun it when a new suite needs covering. The bytes change every time - the
randoms and keys are fresh - so a diff against the old file is noise;
what matters is that the suites listed are the ones we want.
"""
import datetime, ssl, json
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def make_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()).decode())

cert_pem, key_pem = make_cert()
import tempfile, os
cf = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False); cf.write(cert_pem); cf.close()
kf = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False); kf.write(key_pem); kf.close()

captures = {}
for label, (maxv, ciphers) in {
    "tls12_rsa_aes128_sha":   (ssl.TLSVersion.TLSv1_2, "AES128-SHA"),
    "tls12_ecdhe_aes256_sha384": (ssl.TLSVersion.TLSv1_2, "ECDHE-RSA-AES256-GCM-SHA384"),
    "tls13": (ssl.TLSVersion.TLSv1_3, None),
}.items():
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cf.name, kf.name)
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    server_ctx.maximum_version = maxv
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_verify_locations(cf.name)
    client_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    client_ctx.maximum_version = maxv
    if ciphers:
        try:
            server_ctx.set_ciphers(ciphers)
            client_ctx.set_ciphers(ciphers)
        except ssl.SSLError as e:
            print(label, "unavailable:", e); continue

    # SSLKEYLOGFILE gives us the master secret for the session. With it,
    # the transcript stops being only a framing fixture: our key schedule
    # has to derive a key block that decrypts records a real
    # implementation encrypted. A byte wrong anywhere and it does not.
    keylog = tempfile.NamedTemporaryFile("w", suffix=".keylog", delete=False)
    keylog.close()
    client_ctx.keylog_filename = keylog.name

    cin, cout = ssl.MemoryBIO(), ssl.MemoryBIO()
    sin, sout = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_ctx.wrap_bio(cin, cout, server_hostname="localhost")
    server = server_ctx.wrap_bio(sin, sout, server_side=True)

    to_server, to_client = bytearray(), bytearray()
    for _ in range(20):
        for side, out_bio, in_bio, sink in ((client, cout, cin, to_server),
                                            (server, sout, sin, to_client)):
            try:
                side.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
        data = cout.read()
        if data: to_server += data; sin.write(data)
        data = sout.read()
        if data: to_client += data; cin.write(data)
        try:
            client.do_handshake(); server.do_handshake()
            break
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            continue

    try:
        version, suite = client.version(), client.cipher()
    except Exception as e:
        print(label, "failed:", e); continue

    # Application data too, so there are protected records after the handshake.
    client.write(b"hello from the client")
    data = cout.read(); to_server += data; sin.write(data)
    assert server.read(100) == b"hello from the client"

    secrets = {}
    for line in open(keylog.name):
        parts = line.split()
        if len(parts) == 3 and not line.startswith("#"):
            secrets.setdefault(parts[0], []).append((parts[1], parts[2]))
    os.unlink(keylog.name)

    captures[label] = {
        "version": version, "cipher": suite,
        "to_server": bytes(to_server).hex(),
        "to_client": bytes(to_client).hex(),
        "secrets": secrets,
    }
    print(f"{label}: {version} {suite[0]} "
          f"client->server {len(to_server)}B, server->client {len(to_client)}B")

import pathlib

# A line-based format rather than JSON, so the Rust side can read it with
# `split_whitespace` instead of a hand-rolled JSON scanner - which is
# exactly the kind of thing that parses the wrong field and passes anyway.
HEADER = """\
# Real TLS handshakes, captured by scripts/capture_transcripts.py.
#
# Both sides are Python's ssl in memory-BIO mode, pumped by hand - no
# sockets - so this is every byte that crossed between two implementations
# that are not ours. It is the fixture the record layer and the handshake
# state machine are developed against before any live connection, because a
# state machine bug is the category unit tests are worst at catching.
#
# One record per line: "<field> <transcript> <value>". The bytes change on
# every capture (fresh randoms and keys), so a diff against the old file is
# noise; what matters is that the suites listed are the ones we want.
"""

destination = (pathlib.Path(__file__).resolve().parent.parent
               / "tests" / "transcripts" / "handshakes.txt")
with destination.open("w") as out:
    out.write(HEADER)
    for name, capture in captures.items():
        out.write(f"\nversion {name} {capture['version']}\n")
        out.write(f"cipher {name} {capture['cipher'][0]}\n")
        out.write(f"to_server {name} {capture['to_server']}\n")
        out.write(f"to_client {name} {capture['to_client']}\n")
        # The key log's secrets. For TLS 1.2 this is CLIENT_RANDOM with the
        # master secret; for 1.3 it is the traffic secrets, which this
        # library does not derive yet.
        for label_name, entries in capture["secrets"].items():
            for client_random, secret in entries:
                out.write(f"secret {name} {label_name} {client_random} {secret}\n")
print("wrote", destination)
os.unlink(cf.name); os.unlink(kf.name)
