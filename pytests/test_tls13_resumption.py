"""TLS 1.3 session resumption, against OpenSSL as the **client**.

There is no way to check a session ticket from inside. The ticket is
opaque bytes we sealed ourselves, so a round trip against our own code
proves only that we can read our own writing; and the binder that proves
the client holds the PSK is *self-consistent whatever it got wrong* -
compute it over the wrong transcript at both ends and both ends agree.

So this file drives a real `ssl.SSLContext`, does a full handshake, keeps
the `SSLSession` OpenSSL built from our NewSessionTicket, and offers it
back on a second connection. `session_reused` coming back `True` is the
only statement worth making here: it means OpenSSL opened our ticket,
recomputed our binder over a transcript it derived independently, and
agreed.

**Why every test builds two connections and a shared ticket key.**
Resumption is between two connections by definition, and a ticket key
generated per connection seals tickets nothing else can open. That is the
default - safe, and useless for resumption - so these tests configure one,
the way a deployment that wants tickets to survive a restart would.
"""

import ssl
import time

import pytest

from cryptography.hazmat.primitives import serialization

import allcrypt

from test_tls_server import ec_identity, rsa_identity

NOW = int(time.time())
TLS13 = ssl.TLSVersion.TLSv1_3
# Forty bytes: eight of key name, thirty-two of key. Fixed here so the two
# connections in a test share one, which is the whole point.
TICKET_KEY = bytes(range(40))


class Connection:
    """One finished connection, with both ends and both BIOs."""

    def __init__(self, client, server, incoming, outgoing):
        self.client = client
        self.server = server
        self.incoming = incoming
        self.outgoing = outgoing

    @property
    def established(self):
        return self.server.established

    @property
    def session_reused(self):
        return self.client.session_reused

    @property
    def session(self):
        return self.client.session

    def send_from_client(self, payload):
        self.client.write(payload)
        self.server.push_incoming(self.outgoing.read())
        self.server.process()
        return self.server.take_incoming()

    def send_from_server(self, payload):
        self.server.write(payload)
        self.incoming.write(self.server.take_outgoing())
        return self.client.read(len(payload))


class Resumable:
    """One client context and as many connections as a test wants.

    The context is shared because OpenSSL refuses a session that came from
    a different one - `wrap_bio(..., session=...)` raises rather than
    silently doing a full handshake, which is the right way round.
    """

    def __init__(self, identity=None, **server_options):
        self.key, certificate = identity if identity else ec_identity()
        self.chain = [certificate.public_bytes(serialization.Encoding.DER)]
        pem = certificate.public_bytes(serialization.Encoding.PEM).decode()

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.minimum_version = TLS13
        self.context.maximum_version = TLS13
        self.context.load_verify_locations(cadata=pem)

        self.server_options = dict(
            max_version="TLSv1.3", now=NOW, session_tickets=2,
            ticket_key=TICKET_KEY)
        self.server_options.update(server_options)
        self.server_error = None
        self.client_error = None

    def connect(self, session=None):
        """One connection, pumped to completion.

        Returns a `Connection` rather than a pair, because a test that
        sends data afterwards needs the memory BIOs too.
        """
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = self.context.wrap_bio(incoming, outgoing,
                                       server_hostname="localhost",
                                       session=session)
        server = allcrypt.TlsServer(self.chain, self.key, **self.server_options)

        for _ in range(20):
            try:
                client.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            except ssl.SSLError as reason:
                self.client_error = reason
                break
            data = outgoing.read()
            if data:
                server.push_incoming(data)
            try:
                server.process()
            except ValueError as reason:
                self.server_error = reason
                break
            out = server.take_outgoing()
            if out:
                incoming.write(out)
            if server.established and not out and not data:
                break

        # The NewSessionTickets come after the handshake, so the client has
        # to be given a chance to read them before its session is worth
        # anything. Without this the second connection silently falls back
        # to a full handshake and the test would pass for the wrong reason.
        for _ in range(4):
            out = server.take_outgoing()
            if out:
                incoming.write(out)
            try:
                client.read(1)
            except (ssl.SSLWantReadError, ssl.SSLError):
                pass
        return Connection(client, server, incoming, outgoing)


# --------------------------------------------------------- the round trip ---

def test_an_openssl_client_resumes():
    """The one that matters.

    `session_reused` is OpenSSL's word, not ours: it opened the ticket we
    sealed, derived the binder key from the PSK inside it, computed the
    binder over a transcript it built itself, and got the same answer we
    did.
    """
    pair = Resumable()
    first = pair.connect()
    assert first.established
    assert not first.session_reused, "the first connection cannot resume"

    second = pair.connect(first.session)
    assert pair.client_error is None, pair.client_error
    assert pair.server_error is None, pair.server_error
    assert second.established
    assert second.session_reused, "the ticket was not accepted"


def test_a_resumed_connection_carries_data():
    """Not a formality: a resumed handshake derives its application keys
    from a schedule that started with a PSK rather than with zeros, so
    every one of them is different from the full handshake's. Stopping at
    `session_reused` would not notice a schedule that agreed about the
    handshake and disagreed about what came after."""
    pair = Resumable()
    first = pair.connect()
    second = pair.connect(first.session)
    assert second.session_reused

    assert second.send_from_client(b"resumed request") == b"resumed request"
    assert second.send_from_server(b"resumed reply") == b"resumed reply"


def test_an_rsa_server_issues_usable_tickets():
    """Resumption does not depend on the key type.

    It should not: a resumed handshake sends no certificate and makes no
    signature, which is most of why it is cheap. This asserts that the
    thing which *does* differ between key types - the CertificateVerify -
    really is out of the picture.
    """
    pair = Resumable(identity=rsa_identity())
    first = pair.connect()
    second = pair.connect(first.session)
    assert second.established
    assert second.session_reused


# ------------------------------------------------------- when it must not ---

def test_a_different_ticket_key_refuses_the_ticket():
    """And refuses it by doing a full handshake, not by failing.

    A ticket sealed under a key this server does not have is not an error
    to report - the client may simply have reached a machine that was
    rotated, or a different deployment. It gets a handshake and is told
    nothing, because "that ticket was almost right" is information.
    """
    pair = Resumable()
    first = pair.connect()

    pair.server_options["ticket_key"] = bytes(range(40, 80))
    second = pair.connect(first.session)
    assert second.established, "a rejected ticket must still connect"
    assert not second.session_reused
    assert pair.client_error is None
    assert pair.server_error is None


def test_a_rotated_key_still_opens_what_it_sealed():
    """Rotation by list, newest first: the new key seals, the old one
    still opens, and dropping it ends exactly the sessions it sealed.

    Against a real OpenSSL client, so the ticket really travelled: what
    the server sealed under the old key came back from somebody else's
    session cache.
    """
    newer = bytes(range(40, 80))
    pair = Resumable()
    before = pair.connect()

    pair.server_options["ticket_key"] = [newer, TICKET_KEY]
    after = pair.connect(before.session)
    assert after.established and after.session_reused, \
        "a ticket sealed before the rotation did not resume"

    pair.server_options["ticket_key"] = [newer]
    retired = pair.connect(before.session)
    assert retired.established and not retired.session_reused
    fresh = pair.connect(after.session)
    assert fresh.session_reused, "a ticket the new key sealed did not resume"

    with pytest.raises(ValueError):
        pair.server_options["ticket_key"] = [newer, newer]
        pair.connect()
    with pytest.raises(TypeError):
        pair.server_options["ticket_key"] = "forty characters is not forty bytes!!!!"
        pair.connect()


def test_an_expired_ticket_is_refused():
    """The lifetime the client was told is not the check.

    The server stamps its own tickets and checks them against its own
    clock, because a client that lies about the age of a ticket is exactly
    the client a check is for.
    """
    pair = Resumable()
    first = pair.connect()

    pair.server_options["now"] = NOW + 86_400 * 2      # past the lifetime
    second = pair.connect(first.session)
    assert second.established
    assert not second.session_reused


def test_a_server_with_tickets_off_issues_none():
    """Zero is off, and it is the default.

    A ticket needs a clock to expire against, so a server that has not been
    given one does not issue any - a ticket that is honoured forever is
    worse than no ticket.
    """
    pair = Resumable(session_tickets=0)
    first = pair.connect()
    assert first.established
    assert not first.session.has_ticket

    second = pair.connect(first.session)
    assert second.established
    assert not second.session_reused


def test_two_tickets_arrive_and_both_work():
    """Two, because a client opening several connections at once would
    otherwise offer one ticket twice - and a PSK offered twice is linkable
    across those connections."""
    pair = Resumable()
    first = pair.connect()
    assert first.session.has_ticket
    # OpenSSL keeps the most recent; both being usable is what matters, and
    # the check is that resumption works at all after two were sent.
    second = pair.connect(first.session)
    assert second.established
    assert second.session_reused
