"""ALPN negotiation (RFC 7301), both directions, against OpenSSL.

ALPN is a small extension with a large failure mode: both ends agreeing
on a protocol *neither* peer actually chose. Our own client and our own
server would agree about that perfectly - they read and write the same
encoder - so each half is driven against `ssl.SSLContext`, which has
`set_alpn_protocols` on both sides and `selected_alpn_protocol()` to say
what it thinks happened.

Two things that are easy to get wrong and silent when wrong:

* **The answer lives in a different message in each version.** At TLS 1.2
  it is in the ServerHello, in the clear; at 1.3 it is in
  EncryptedExtensions. A server that wrote it into the 1.3 ServerHello
  would be announcing the application protocol to the network, and every
  test between our own ends would still pass.
* **Whose order decides.** The server's, which means a test where both
  ends list the same protocols in the same order cannot tell a correct
  implementation from one that takes the client's. Every test here lists
  them in opposite orders.
"""

import ssl
import time

import pytest

from cryptography.hazmat.primitives import serialization

import allcrypt

from test_tls_server import ec_identity

NOW = int(time.time())
PEM = serialization.Encoding.PEM
DER = serialization.Encoding.DER
TLS12 = ssl.TLSVersion.TLSv1_2
TLS13 = ssl.TLSVersion.TLSv1_3


# ------------------------------------------- our server, OpenSSL's client ---

class OurServer:
    """An OpenSSL client and our server over memory BIOs."""

    def __init__(self, *, client_alpn=None, version=TLS13, **options):
        self.key, certificate = ec_identity()
        chain = [certificate.public_bytes(DER)]

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = version
        context.maximum_version = version
        context.load_verify_locations(
            cadata=certificate.public_bytes(PEM).decode())
        if client_alpn is not None:
            context.set_alpn_protocols(client_alpn)

        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.client = context.wrap_bio(self.incoming, self.outgoing,
                                       server_hostname="localhost")
        name = {TLS12: "TLSv1.2", TLS13: "TLSv1.3"}[version]
        options.setdefault("now", NOW)
        options.setdefault("min_version", name)
        options.setdefault("max_version", name)
        self.server = allcrypt.TlsServer(chain, self.key, **options)
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
def test_the_servers_order_decides(version):
    """Both ends offer the same two protocols in opposite orders.

    Written that way on purpose: with matching orders, a server that
    took the *client's* preference would produce the same answer and
    this test could not tell the two apart.
    """
    run = OurServer(client_alpn=["http/1.1", "h2"], version=version,
                    alpn=["h2", "http/1.1"]).pump()
    assert run.server_error is None, run.server_error
    assert run.client_error is None, run.client_error
    assert run.server.established
    assert run.client.selected_alpn_protocol() == "h2"
    assert run.server.selected_alpn_protocol() == "h2"
    # And the offer is reported whole, chosen or not.
    assert run.server.offered_alpn == ["http/1.1", "h2"]


@pytest.mark.parametrize("version", [TLS12, TLS13])
def test_a_client_that_offers_nothing_gets_nothing(version):
    run = OurServer(version=version, alpn=["h2", "http/1.1"]).pump()
    assert run.server.established
    assert run.client.selected_alpn_protocol() is None
    assert run.server.selected_alpn_protocol() is None
    assert run.server.offered_alpn == []


@pytest.mark.parametrize("version", [TLS12, TLS13])
def test_a_server_that_offers_nothing_answers_nothing(version):
    """The default, and it has to stay silent rather than pick.

    A proxy that answered `h2` on behalf of something speaking HTTP/1.1
    would have promised a protocol nothing behind it can deliver, so
    "negotiate the first thing the client asked for" is not a safe
    default and is not the default.
    """
    run = OurServer(client_alpn=["h2", "http/1.1"], version=version).pump()
    assert run.server.established
    assert run.client.selected_alpn_protocol() is None
    assert run.server.selected_alpn_protocol() is None
    assert run.server.offered_alpn == ["h2", "http/1.1"]


@pytest.mark.parametrize("version", [TLS12, TLS13])
def test_nothing_in_common_connects_by_default(version):
    """RFC 7301 3.1 read the careful way.

    A server with nothing in common may fail or carry on without the
    extension. Carrying on is right when the protocol is settled some
    other way - a URL scheme, a port - and that is the common case, so
    it is the default.
    """
    run = OurServer(client_alpn=["spdy/3"], version=version,
                    alpn=["h2", "http/1.1"]).pump()
    assert run.server_error is None, run.server_error
    assert run.server.established
    assert run.client.selected_alpn_protocol() is None
    assert run.server.selected_alpn_protocol() is None


@pytest.mark.parametrize("version", [TLS12, TLS13])
def test_require_alpn_refuses_when_nothing_matches(version):
    """And it is a *different* alert from every other failure.

    `no_application_protocol` (120) exists so a client can tell "we have
    no protocol in common" from "your certificate is bad" - which is
    worth having, because the remedies have nothing to do with each
    other.
    """
    run = OurServer(client_alpn=["spdy/3"], version=version,
                    alpn=["h2"], require_alpn=True).pump()
    assert not run.server.established
    assert run.server_error is not None
    assert "no_application_protocol" in str(run.server_error)


@pytest.mark.parametrize("version", [TLS12, TLS13])
def test_require_alpn_ignores_a_client_that_offered_none(version):
    """A client that sent no extension has not disagreed with anybody.

    Failing here would make `require_alpn` mean "refuse every client
    that does not do ALPN", which is a different and much larger
    setting than the one it is named for.
    """
    run = OurServer(version=version, alpn=["h2"], require_alpn=True).pump()
    assert run.server.established
    assert run.server.selected_alpn_protocol() is None


def test_the_answer_is_encrypted_at_tls13():
    """**Where the answer lives is the version-specific part.**

    At 1.2 it is in the ServerHello, in the clear. At 1.3 it belongs in
    EncryptedExtensions, and a server that left it in the ServerHello
    would announce the application protocol to the network - while every
    test above still passed, because our client and OpenSSL's both
    accept it wherever our server puts it.

    So this reads the bytes. The server's first flight at 1.3 carries the
    ServerHello unencrypted; `h2` must not appear in it.
    """
    run = OurServer(client_alpn=["h2"], version=TLS13, alpn=["h2"]).pump()
    assert run.server.selected_alpn_protocol() == "h2"

    plain = OurServer(client_alpn=["h2"], version=TLS13, alpn=["h2"])
    plain.client.do_handshake_on_connect = False
    try:
        plain.client.do_handshake()
    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
        pass
    plain.server.push_incoming(plain.outgoing.read())
    plain.server.process()
    flight = plain.server.take_outgoing()
    # The ServerHello is the first record and is not protected; anything
    # after the handshake keys go in is. Finding "h2" anywhere in the
    # first record would mean it was written in the clear.
    first_record_length = int.from_bytes(flight[3:5], "big")
    assert b"h2" not in flight[:5 + first_record_length], \
        "the ALPN answer is in the plaintext ServerHello"


def test_a_protocol_the_client_did_not_offer_is_refused():
    """Our *client*'s check, and it needs a server that misbehaves.

    No real peer does this, so the message is built by hand: a real
    handshake is driven up to the ServerHello and the answer is put
    where a correct server would never put it. Without the check, an
    application ends up speaking a protocol it never agreed to, chosen
    by whoever is on the wire.
    """
    roots = allcrypt.TrustStore()
    client = allcrypt.TlsClient("localhost", roots, now=NOW, verify=False,
                                min_version="TLSv1.2", max_version="TLSv1.2",
                                alpn=["http/1.1"])
    # A ServerHello carrying an ALPN answer of "h2", which was not
    # offered. Built from the client's own hello so the suite is one it
    # will accept.
    hello = client.take_outgoing()
    assert hello
    reply = _server_hello_with_alpn(b"h2")
    client.push_incoming(reply)
    with pytest.raises(ValueError) as failure:
        client.process()
    assert "did not offer" in str(failure.value)


# ------------------------------------------ our client, OpenSSL's server ---

class OurClient:
    """Our client and an OpenSSL server, over memory BIOs.

    The half our own server cannot judge: it encodes the offer with the
    same function it would decode with, so a wrong wire shape would
    round-trip perfectly between our two ends.
    """

    def __init__(self, tmp_path, *, server_alpn=None, client_alpn=(),
                 version=TLS13):
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
        context.minimum_version = version
        context.maximum_version = version
        context.load_cert_chain(str(identity))
        if server_alpn is not None:
            context.set_alpn_protocols(server_alpn)

        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.server = context.wrap_bio(self.incoming, self.outgoing,
                                       server_side=True)

        roots = allcrypt.TrustStore()
        roots.add_pem(certificate.public_bytes(PEM).decode())
        name = {TLS12: "TLSv1.2", TLS13: "TLSv1.3"}[version]
        self.client = allcrypt.TlsClient("localhost", roots, now=NOW,
                                         min_version=name, max_version=name,
                                         alpn=list(client_alpn))
        self.client_error = None
        self.server_error = None

    def pump(self, rounds=20):
        for _ in range(rounds):
            out = self.client.take_outgoing()
            if out:
                self.incoming.write(out)
            try:
                self.server.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            except ssl.SSLError as reason:
                self.server_error = reason
            data = self.outgoing.read()
            if data:
                self.client.push_incoming(data)
                try:
                    self.client.process()
                except ValueError as reason:
                    self.client_error = reason
                    break
            if self.server_error:
                break
            if self.client.established and not out and not data:
                break
        return self


@pytest.mark.parametrize("version", [TLS12, TLS13])
def test_an_openssl_server_reads_our_offer(version):
    """The one that matters for our client.

    OpenSSL parsed the list we wrote - the two-byte outer length, the
    one-byte name lengths - and chose from it. Our own server would have
    parsed whatever we produced, because it uses the same encoder.

    Opposite orders again: OpenSSL applies the *server's* preference, so
    `h2` coming back proves it read both names rather than taking the
    first thing in our list.
    """
    import tempfile, pathlib
    tmp = pathlib.Path(tempfile.mkdtemp())
    run = OurClient(tmp, server_alpn=["h2", "http/1.1"],
                    client_alpn=["http/1.1", "h2"], version=version).pump()
    assert run.client_error is None, run.client_error
    assert run.server_error is None, run.server_error
    assert run.client.established
    assert run.client.selected_alpn_protocol() == "h2"
    assert run.server.selected_alpn_protocol() == "h2"


@pytest.mark.parametrize("version", [TLS12, TLS13])
def test_a_server_with_nothing_in_common_leaves_us_connected(version):
    import tempfile, pathlib
    tmp = pathlib.Path(tempfile.mkdtemp())
    run = OurClient(tmp, server_alpn=["spdy/3"], client_alpn=["h2"],
                    version=version).pump()
    # OpenSSL's server fails the handshake on no overlap, which is the
    # other half of RFC 7301 3.1 and its own choice, not ours. What is
    # asserted here is only that we never claim a protocol.
    assert run.client.selected_alpn_protocol() is None


@pytest.mark.parametrize("version", [TLS12, TLS13])
def test_we_offer_nothing_when_the_list_is_empty(version):
    import tempfile, pathlib
    tmp = pathlib.Path(tempfile.mkdtemp())
    run = OurClient(tmp, server_alpn=["h2"], version=version).pump()
    assert run.client.established
    assert run.client.selected_alpn_protocol() is None
    assert run.server.selected_alpn_protocol() is None


def test_an_answer_naming_two_protocols_is_refused():
    """RFC 7301 4.2: the server selects **one**.

    A list of two is a server that has not chosen, and taking the first
    one for it means the two ends can end up disagreeing about which was
    picked. No real peer sends this - which is exactly why it needs a
    hand-built message: the deliberate-breakage sweep found that
    removing the check failed nothing at all.
    """
    roots = allcrypt.TrustStore()
    client = allcrypt.TlsClient("localhost", roots, now=NOW, verify=False,
                                min_version="TLSv1.2", max_version="TLSv1.2",
                                alpn=["h2", "http/1.1"])
    assert client.take_outgoing()
    client.push_incoming(_server_hello_with_alpn(b"h2", b"http/1.1"))
    with pytest.raises(ValueError) as failure:
        client.process()
    assert "more than one" in str(failure.value)


def _server_hello_with_alpn(*protocols):
    """A minimal TLS 1.2 ServerHello whose only extension is ALPN.

    Takes several names so a test can build the answer a correct server
    never sends.
    """
    names = b"".join(bytes([len(name)]) + name for name in protocols)
    alpn = len(names).to_bytes(2, "big") + names
    extensions = bytes([0, 16]) + len(alpn).to_bytes(2, "big") + alpn
    body = (b"\x03\x03" + bytes(32) + b"\x00"
            + b"\xc0\x2f"                    # ECDHE_RSA_AES128_GCM_SHA256
            + b"\x00"
            + len(extensions).to_bytes(2, "big") + extensions)
    message = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(message).to_bytes(2, "big") + message
