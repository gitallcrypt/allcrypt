"""The hybrid post-quantum key exchange groups of RFC 10024, at TLS 1.3.

X25519MLKEM768 and the two NIST-curve hybrids: ML-KEM (FIPS 203)
combined with a classical exchange, so a connection stays confidential
if either half is broken.

**What these tests can and cannot establish.** Nothing on this machine
speaks these groups - OpenSSL here is 3.0 and gained them in 3.5 - so a
handshake that negotiates one is our client talking to our server, which
proves the wiring (both sides agree on the share layout and the secret)
and nothing about whether the layout is the RFC's. The share layout and
secret order are checked separately in `src/tls/kex.rs`'s tests, by
building the server's answer from the ML-KEM and X25519 primitives; the
primitives themselves are checked against NIST's and RFC 7748's numbers.
A check against an implementation that is not this library is still
owed.

What *is* checked against OpenSSL here is the thing that would break
existing connections: a ClientHello carrying a 1.2 KB hybrid share and
three unknown groups at the front of supported_groups still completes
against a server that knows none of them.
"""

import ssl
import time

import pytest

from cryptography.hazmat.primitives import serialization

import allcrypt

from test_tls_server import ec_identity

NOW = int(time.time())
PEM = serialization.Encoding.PEM


class Ours:
    """Our client and our server, over memory."""

    def __init__(self, client_max="TLSv1.3", server_max="TLSv1.3"):
        key, certificate = ec_identity()
        chain = [certificate.public_bytes(serialization.Encoding.DER)]
        roots = allcrypt.TrustStore()
        roots.add_pem(certificate.public_bytes(PEM).decode())
        self.server = allcrypt.TlsServer(chain, key, now=NOW,
                                         max_version=server_max)
        self.client = allcrypt.TlsClient("localhost", roots, now=NOW,
                                         min_version="TLSv1.2",
                                         max_version=client_max)

    def pump(self, rounds=20):
        for _ in range(rounds):
            out = self.client.take_outgoing()
            if out:
                self.server.push_incoming(out)
                self.server.process()
            back = self.server.take_outgoing()
            if back:
                self.client.push_incoming(back)
                self.client.process()
            if self.client.established and not out and not back:
                break
        return self


def test_our_client_and_server_negotiate_x25519mlkem768():
    run = Ours().pump()
    assert run.client.established and run.server.established
    assert run.client.version() == "TLSv1.3"
    assert run.client.named_group == "X25519MLKEM768"

    # Keys that agree, not merely a Finished that matched.
    run.client.write(b"over a post-quantum key")
    run.server.push_incoming(run.client.take_outgoing())
    run.server.process()
    assert run.server.take_incoming() == b"over a post-quantum key"


def test_a_tls12_connection_uses_no_hybrid_group():
    """The hybrids are TLS 1.3 only; a 1.2 connection between the same two
    ends falls back to a classical group."""
    run = Ours(server_max="TLSv1.2").pump()
    assert run.client.established
    assert run.client.version() == "TLSv1.2"
    assert "MLKEM" not in (run.client.named_group or "")


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_3,
                                     ssl.TLSVersion.TLSv1_2])
def test_a_server_that_knows_no_hybrid_still_connects(tmp_path, version):
    """OpenSSL 3.0 has never heard of 0x11EC. Our hello leads with it -
    in supported_groups and as the first key share - and the server must
    skip it and pick X25519, with no retry."""
    from cryptography.hazmat.primitives.asymmetric import ec as pyec
    from test_tls_server import make_cert

    private = pyec.generate_private_key(pyec.SECP256R1())
    certificate = make_cert(private)
    identity = tmp_path / "server.pem"
    identity.write_bytes(
        certificate.public_bytes(PEM)
        + private.private_bytes(PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = version
    context.load_cert_chain(str(identity))
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    server = context.wrap_bio(incoming, outgoing, server_side=True)

    roots = allcrypt.TrustStore()
    roots.add_pem(certificate.public_bytes(PEM).decode())
    client = allcrypt.TlsClient("localhost", roots, now=NOW,
                                min_version="TLSv1.2", max_version="TLSv1.3")
    for _ in range(20):
        out = client.take_outgoing()
        if out:
            incoming.write(out)
        try:
            server.do_handshake()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        data = outgoing.read()
        if data:
            client.push_incoming(data)
            client.process()
        if client.established and not out and not data:
            break
    assert client.established
    assert client.named_group == "x25519"
