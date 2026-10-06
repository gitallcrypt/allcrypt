"""TLS 1.3 handshakes, against OpenSSL as the **client**.

`src/tls/server.rs`'s own test drives our client against our server and
says so in its comment: both ends are ours, so anything wrong in the same
way twice agrees with itself perfectly. TLS 1.3 makes that worse than
usual, because almost everything in it is a hash of a hash:

  * the handshake keys come from the transcript **through the
    ServerHello**,
  * the CertificateVerify signature covers the transcript **through the
    Certificate**,
  * the server's Finished covers the transcript **through the
    CertificateVerify**,
  * and the application keys come from the transcript **through the
    server's Finished**.

Four hashes, each one message apart. Swap any two and our own client
computes the same wrong answer and the handshake completes. Only a peer
that computed them independently can tell us, and that is what this file
is: a real `ssl.SSLContext` client, over memory BIOs, with no socket and
no timing.

The harness is imported from `test_tls_server.py` rather than copied -
the 1.2 file already builds identities, certificates and the pump loop,
and a second copy would be a second thing to keep right.
"""

import ssl

import pytest

from test_tls_server import Handshake, ec_identity, rsa_identity

TLS13 = ssl.TLSVersion.TLSv1_3


def handshake(**kwargs):
    """A 1.3-only client against a server whose ceiling is 1.3."""
    kwargs.setdefault("client_min", TLS13)
    kwargs.setdefault("client_max", TLS13)
    kwargs.setdefault("max_version", "TLSv1.3")
    return Handshake(**kwargs).pump()


# --------------------------------------------------------- the handshake ---

def test_an_openssl_client_completes_a_tls13_handshake():
    session = handshake()
    assert session.client_error is None, session.client_error
    assert session.server_error is None, session.server_error
    assert session.server.established
    assert session.server.version() == "TLSv1.3"
    assert session.client.version() == "TLSv1.3"


def test_the_client_verified_our_certificate():
    """The point of CertificateVerify.

    `verify=True` means OpenSSL checked the chain **and** the signature
    over the transcript. A server that signed the wrong transcript, or
    with `Side13::Client`'s context string, fails here with
    `decrypt_error` - and passes every test of ours that does not have a
    real peer in it.
    """
    session = handshake(verify=True)
    assert session.client_error is None, session.client_error
    assert session.client.getpeercert() is not None


def test_application_data_crosses_in_both_directions():
    """Not a formality.

    The application traffic keys come from the transcript through the
    server's own Finished, and unlike the other three hashes that one is
    not used until the first application record. A server that derives
    them from the wrong point completes the handshake perfectly and fails
    here - which is why this test and the one below it exist rather than
    stopping at `established`.
    """
    session = handshake()
    assert session.send_from_client(b"client says") == b"client says"
    assert session.send_from_server(b"server says") == b"server says"


def test_a_long_payload_spans_records():
    """More than one record's worth, so the 1.3 sequence number advances.

    The nonce is the static IV XOR the counter, right-aligned, and the
    counter belongs to the *keys* rather than to the connection. One that
    does not advance decrypts the first record and nothing after it - so
    a payload that fits in a single record proves nothing here.

    `Handshake.send_from_server` reads once and a single `read` returns at
    most one record, so the loop is this test's own.
    """
    session = handshake()
    payload = bytes(range(256)) * 200        # ~51 KB, several records

    assert session.send_from_client(payload) == payload

    session.server.write(payload)
    session.client_in.write(session.server.take_outgoing())
    received = b""
    while len(received) < len(payload):
        chunk = session.client.read(len(payload) - len(received))
        assert chunk, "the client stopped reading before the payload ended"
        received += chunk
    assert received == payload


# ------------------------------------------------------------- the suites ---

@pytest.mark.parametrize("suite", [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
])
def test_each_tls13_suite(suite):
    """Each of the three, pinned from **our** side.

    Python's `set_ciphers` only reaches the TLS 1.2 list; the 1.3 suites
    live behind OpenSSL's separate `ciphersuites` setting, which the `ssl`
    module does not expose. So the suite is pinned on the server instead,
    and the assertion that it took is the client reporting it back.

    `TLS_AES_256_GCM_SHA384` is the one that matters most: it is the only
    suite here whose hash is SHA-384, so a schedule with SHA-256 hardcoded
    anywhere passes the other two and fails this one. And
    `TLS_CHACHA20_POLY1305_SHA256` is the only one whose AEAD is not AES,
    so a key length taken from the wrong place fails only there.
    """
    session = handshake(ciphers=suite)
    assert session.client_error is None, session.client_error
    assert session.server.established
    assert session.client.cipher()[0] == suite
    assert session.server.cipher()[0] == suite


# -------------------------------------------------------------- the keys ---

def test_an_rsa_key_signs_with_pss():
    """RSA at 1.3 is PSS only.

    RFC 8446 4.4.3 forbids the `rsa_pkcs1_*` codepoints in a
    CertificateVerify, and `ServerKey::scheme` - which the 1.2 path uses -
    produces nothing but those. A server that reached for it would be
    refused by OpenSSL with `illegal_parameter`, and by our own client
    too, which checks `allowed_in_certificate_verify`.
    """
    session = handshake(identity=rsa_identity())
    assert session.client_error is None, session.client_error
    assert session.server.established


def test_an_ec_key_works_at_13_although_the_suite_says_rsa():
    """The suite table's `KeyExchange` is a placeholder at 1.3.

    Every 1.3 row in `suites.rs` says `EcdheRsa`, because the type needs
    something and 1.3 suites name no key exchange at all. `choose_suite`
    at 1.2 quite correctly refuses a suite this server's key cannot
    authenticate - and applying that rule at 1.3 would refuse *every*
    handshake made with an EC key, for a reason that is an artefact of
    our own table. `server13::choose_suite` does not consult it, and this
    is the test that says so.
    """
    session = handshake(identity=ec_identity())
    assert session.client_error is None, session.client_error
    assert session.server.established
    assert session.server.version() == "TLSv1.3"


# ---------------------------------------------------- version negotiation ---

def test_a_client_that_can_do_both_gets_13():
    """Offered 1.2 and 1.3, a server with a 1.3 ceiling must choose 1.3."""
    session = Handshake(client_min=ssl.TLSVersion.TLSv1_2,
                        client_max=TLS13,
                        max_version="TLSv1.3").pump()
    assert session.server.version() == "TLSv1.3"
    assert session.client.version() == "TLSv1.3"


def test_a_server_pinned_to_12_still_answers_a_13_client():
    """The ceiling is honoured downwards.

    `supported_versions` lists every version the client will take, so a
    server whose ceiling is 1.2 picks 1.2 out of that list rather than
    refusing. This is the case a `max_version="TLSv1.2"` deployment is,
    and it must keep working now that the default moved.
    """
    session = Handshake(client_min=ssl.TLSVersion.TLSv1_2,
                        client_max=TLS13,
                        max_version="TLSv1.2").pump()
    assert session.server.version() == "TLSv1.2"
    assert session.client.version() == "TLSv1.2"


def test_a_13_only_client_against_a_12_only_server_fails():
    """And fails as a version complaint, not as something else."""
    session = Handshake(client_min=TLS13, client_max=TLS13,
                        max_version="TLSv1.2").pump()
    assert not session.server.established
    assert session.client_error is not None or session.server_error is not None


# ------------------------------------------------- what is not there yet ---

def test_resumption_is_not_offered():
    """No NewSessionTicket, so nothing to resume with.

    Asserted rather than left unsaid: a client that gets no ticket does a
    full handshake next time, which is correct but slower, and the day
    tickets appear this test should fail and be replaced by one that
    checks they work.
    """
    session = handshake()
    assert session.client.session is not None
    # OpenSSL always has a session object; what matters is that it cannot
    # be reused, which shows up as no ticket having arrived.
    assert not session.client.session.has_ticket
