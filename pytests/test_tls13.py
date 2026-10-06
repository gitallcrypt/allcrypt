"""Complete TLS 1.3 handshakes, against OpenSSL as the server.

The end-to-end test for everything in `keys13`, `record13` and
`handshake13`: our key schedule, our record layer, our certificate
verification and our state machine, talking to a real TLS 1.3 server.
Memory BIOs on both sides, no socket, no timing.

Why this and not only unit tests: every mistake in a TLS 1.3 key schedule
is *self-consistent*. A label prefix without its trailing space, a nonce
XORed at the wrong end of the IV, an AAD built from the plaintext length -
each of those decrypts its own records perfectly. Only a peer that is not
us can tell.

As in `test_tls_handshake.py`, the tests that matter most are the ones
where the handshake must **fail**. A client that completes every handshake
it is offered passes every happy-path test and authenticates nothing.
"""

import ssl

import pytest

from cryptography.hazmat.primitives.asymmetric import ec

import allcrypt

from test_tls_handshake import Handshake, make_server_cert


def tls13(**options):
    """A handshake with both ends pinned to TLS 1.3.

    `ciphers=None` because the TLS 1.3 suites are not configured through
    `set_ciphers` - that list is the 1.2 one, and setting it to a 1.2 name
    would leave the 1.3 suites untouched while looking like it had done
    something.
    """
    settings = dict(ciphers=None,
                    server_min=ssl.TLSVersion.TLSv1_3,
                    server_max=ssl.TLSVersion.TLSv1_3,
                    min_version="TLSv1.2", max_version="TLSv1.3")
    settings.update(options)
    return Handshake(**settings)


@pytest.fixture
def exchange():
    made = []

    def build(**options):
        made.append(tls13(**options))
        return made[-1]

    yield build
    for one in made:
        one.cleanup()


# --------------------------------------------------------------- it works ---

def test_a_complete_tls13_handshake(exchange):
    """Our HKDF-Expand-Label, our record nonce, our AAD, our transcript and
    our CertificateVerify check, against OpenSSL."""
    run = exchange().pump()

    assert run.client_error is None, f"client failed: {run.client_error}"
    assert run.client.established, f"state is {run.client.state}"
    assert run.client.version() == "TLSv1.3"

    name, strength, bits = run.client.cipher()
    assert name.startswith("TLS_"), name
    assert strength == "modern"
    assert bits >= 128


def test_application_data_flows_both_ways(exchange):
    """The application epoch: new keys, and the sequence number back at
    zero. A record layer that carried the handshake count across would
    compute a nonce the server does not use, and this is where it shows."""
    run = exchange().pump()
    assert run.client.established

    assert run.send(b"from the client") == b"from the client"
    assert run.receive(b"from the server") == b"from the server"

    # More than one record in each direction, so the counter is exercised
    # rather than only its first value.
    for n in range(5):
        message = f"record {n}".encode()
        assert run.send(message) == message


def test_the_certificate_is_actually_verified(exchange):
    """In TLS 1.2 a signature is only present when there is a key exchange
    to sign. In 1.3 the CertificateVerify signs the transcript every time,
    so an unauthenticated 1.3 handshake is not a shape the protocol has."""
    run = exchange().pump()
    assert run.client.established
    assert run.client.certificate_verified
    assert len(run.client.peer_certificates) >= 1


@pytest.mark.parametrize("curve", ["prime256v1"])
def test_both_offered_key_share_groups_work(exchange, curve):
    """The client sends a share for X25519 and P-256.

    Only P-256 is pinned here: `set_ecdh_curve` takes OpenSSL's NIST curve
    names and will not accept "x25519", so the X25519 path is the one the
    unpinned tests above take - OpenSSL prefers it.
    """
    run = exchange(server_ecdh_curve=curve).pump()
    assert run.client_error is None, f"{curve}: {run.client_error}"
    assert run.client.established
    assert run.client.version() == "TLSv1.3"


def test_an_ecdsa_certificate_works(exchange):
    """TLS 1.3 binds the curve to the signature scheme, which TLS 1.2 did
    not: a P-256 key may only sign with ecdsa_secp256r1_sha256. The check
    for that is only exercised by an EC certificate."""
    key = ec.generate_private_key(ec.SECP256R1())
    key, certificate = make_server_cert(key=key)
    run = exchange(key=key, certificate=certificate).pump()

    assert run.client_error is None, f"client failed: {run.client_error}"
    assert run.client.established
    assert run.client.version() == "TLSv1.3"


# --------------------------------------------------- version negotiation ---

def test_a_12_only_server_gets_a_12_handshake(exchange):
    """The client offers 1.3 and 1.2. `supported_versions` is where the
    answer comes from, and a server that does not send one is a 1.2
    server - reading only the hello's version field would see 1.2 either
    way and get it right by accident."""
    run = exchange(server_min=ssl.TLSVersion.TLSv1_2,
                   server_max=ssl.TLSVersion.TLSv1_2,
                   ciphers="ECDHE-RSA-AES128-GCM-SHA256").pump()

    assert run.client_error is None, f"client failed: {run.client_error}"
    assert run.client.established
    assert run.client.version() == "TLSv1.2"


def test_a_13_only_server_and_a_12_only_client_do_not_connect(exchange):
    """The other direction, and it must fail rather than fall back."""
    run = exchange(max_version="TLSv1.2",
                   ciphers="ECDHE-RSA-AES128-GCM-SHA256").pump()
    assert not run.client.established


# ------------------------------------------------------ it refuses things ---

def test_an_untrusted_certificate_is_refused(exchange):
    """A chain that does not reach a root we trust. The whole point of the
    CertificateVerify is that it proves the *certificate* signed the
    transcript, and that means nothing if the certificate is not trusted."""
    other_key, other_certificate = make_server_cert(common_name="somewhere.else")
    from cryptography.hazmat.primitives import serialization
    unrelated = other_certificate.public_bytes(serialization.Encoding.PEM).decode()

    run = exchange(roots_pem=unrelated).pump()
    assert not run.client.established
    assert run.client_error is not None
    assert "root" in str(run.client_error).lower() \
        or "trust" in str(run.client_error).lower(), str(run.client_error)


def test_a_wrong_hostname_is_refused(exchange):
    """The certificate is for localhost and we asked for something else."""
    run = exchange(hostname="not.localhost").pump()
    assert not run.client.established
    assert run.client_error is not None


def test_an_expired_certificate_is_refused(exchange):
    key, certificate = make_server_cert(not_after_days=-1)
    run = exchange(key=key, certificate=certificate).pump()
    assert not run.client.established
    assert run.client_error is not None


# ----------------------------------------------------- the 1.2 relics ---

def test_the_middlebox_change_cipher_spec_is_sent(exchange):
    """RFC 8446 appendix D.4. It means nothing and is not in the
    transcript; it exists so a network appliance watching for the shape of
    a TLS 1.2 handshake lets the connection through. A client that skips
    it works everywhere the test suite runs and fails on somebody's
    corporate network."""
    run = exchange()

    # One pump round is enough to get the ServerHello answered.
    run.pump()
    assert run.client.established

    # Everything we sent, reassembled: the ClientHello in the clear, then
    # a ChangeCipherSpec, then the protected Finished.
    sent = run.server_in  # already consumed; re-derive from a fresh run
    del sent

    fresh = tls13()
    try:
        # Pump by hand so the client's output can be inspected.
        data = fresh.client.take_outgoing()
        fresh.server_in.write(data)
        assert data[0] == 0x16, "the first record is the ClientHello"
        try:
            fresh.server.do_handshake()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        fresh.client.push_incoming(fresh.server_out.read())
        fresh.client.process()

        second = fresh.client.take_outgoing()
        assert second[0] == 0x14, \
            f"expected a ChangeCipherSpec first, got record type {second[0]:#04x}"
        assert second[1:5] == b"\x03\x03\x00\x01"
        assert second[5] == 0x01
        # And what follows it is protected, so its header claims
        # application_data whatever it carries.
        assert second[6] == 0x17, \
            "the Finished must be protected and framed as application_data"
    finally:
        fresh.cleanup()


def test_a_hello_retry_request_completes(exchange):
    """A server wanting a group we sent no share for.

    P-384 is in `supported_groups` and not in the key shares, so OpenSSL
    sends a real HelloRetryRequest - which is the point of driving this
    through OpenSSL rather than through a hand-built message. The
    transcript RFC 8446 section 4.4.1 asks for replaces the first
    ClientHello with a hash of itself, and getting that wrong shows up
    only here, as a Finished that does not match.
    """
    run = exchange(server_ecdh_curve="secp384r1").pump()

    assert run.client_error is None, run.client_error
    assert run.client.established
    assert run.client.version() == "TLSv1.3"
    assert run.client.certificate_verified
    # The retry moved us onto the group the server asked for, not the
    # one we sent a share for.
    assert run.client.named_group in ("P-384", "secp384r1"), \
        run.client.named_group


def test_a_p521_only_server_is_reached_by_a_retry(exchange):
    """P-521 for the exchange and for the certificate, at 1.3.

    The client sends no P-521 share - it is last in supported_groups, for
    a server with nothing else - so this is a HelloRetryRequest onto it,
    then an ecdsa_secp521r1_sha512 CertificateVerify, the one scheme 1.3
    allows a P-521 key."""
    key = ec.generate_private_key(ec.SECP521R1())
    key, certificate = make_server_cert(key=key)
    run = exchange(key=key, certificate=certificate,
                   server_ecdh_curve="secp521r1").pump()
    assert run.client_error is None, run.client_error
    assert run.client.established
    assert run.client.version() == "TLSv1.3"
    assert run.client.certificate_verified
    assert run.client.named_group in ("P-521", "secp521r1"), \
        run.client.named_group
    assert run.send(b"over P-521") == b"over P-521"


def test_application_data_flows_after_a_hello_retry_request(exchange):
    """The keys a retry produces have to work, not merely agree.

    A transcript that was wrong in a way both ends shared would still
    finish the handshake; records that decrypt are a stronger claim.
    """
    run = exchange(server_ecdh_curve="secp384r1").pump()
    assert run.client.established, run.client_error
    assert run.send(b"after the retry") == b"after the retry"
    assert run.receive(b"and back") == b"and back"
