"""Complete TLS handshakes, against OpenSSL as the server.

This is the end-to-end test: our record layer, key schedule, certificate
verification, state machine and RSA key exchange, against a real server.
Everything on our side of the wire is this library's own code, down to the
bignum arithmetic.

Both sides run over memory BIOs and are pumped by hand, so there is no
socket, no timing and no flakiness. A failure here is a protocol bug, not a
network one.

The tests that matter most are the ones where the handshake must **fail**.
A client that completes every handshake it is offered passes every
happy-path test and authenticates nothing.
"""

import datetime
import ssl
import tempfile
import time
import os

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import allcrypt

NOW = int(time.time())


def usage(**flags):
    defaults = dict(digital_signature=False, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False)
    defaults.update(flags)
    return x509.KeyUsage(**defaults)


def make_server_cert(common_name="localhost", sans=("localhost",),
                     key_size=2048, hash_algorithm=None, not_after_days=3650,
                     key=None):
    """A self-signed server certificate, which is both leaf and root here."""
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)

    # A negative not_after_days means "expired this long ago", which needs
    # not_before moved back as well - a certificate whose validity window
    # runs backwards is not an expired certificate, it is an invalid one,
    # and `cryptography` refuses to build it.
    not_after = now + datetime.timedelta(days=not_after_days)
    not_before = min(now - datetime.timedelta(days=1),
                     not_after - datetime.timedelta(days=365))

    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(1)
               .not_valid_before(not_before)
               .not_valid_after(not_after)
               .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                              critical=True)
               .add_extension(usage(digital_signature=True, key_encipherment=True,
                                    key_cert_sign=True, crl_sign=True),
                              critical=True)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                              critical=False))
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in sans]),
            critical=False)

    certificate = builder.sign(key, hash_algorithm or hashes.SHA256())
    return key, certificate


def pem_files(key, certificate):
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    # **An RFC 8410 key has no "traditional" form.** TraditionalOpenSSL
    # means PKCS#1 for RSA and SEC1 for EC, and Ed25519 has neither -
    # `cryptography` raises "format is invalid with this key". PKCS#8 is
    # the only serialisation RFC 8410 defines, so fall back to it rather
    # than special-casing the key type at every call site.
    try:
        key_pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()).decode()
    except ValueError:
        key_pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
    cert_file = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    cert_file.write(cert_pem)
    cert_file.close()
    key_file = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    key_file.write(key_pem)
    key_file.close()
    return cert_pem, cert_file.name, key_file.name


# The two MODP groups a DHE server is likely to be configured with, from
# RFC 2409 section 6.2 and RFC 3526 section 3. Written out rather than
# generated: `openssl dhparam 2048` takes minutes, and a test that waits
# minutes is a test that gets deleted.
MODP_GROUPS = {
    1024: int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
        "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE65381FFFFFFFFFFFFFFFF", 16),
    2048: int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
        "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
        "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
        "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFF"
        "FFFFFFFF", 16),
}

_dh_param_files = {}


def dh_params_file(bits):
    """A PKCS#3 parameter file for one of the groups above, written once."""
    if bits not in _dh_param_files:
        from cryptography.hazmat.primitives.asymmetric import dh as _dh
        parameters = _dh.DHParameterNumbers(MODP_GROUPS[bits], 2).parameters()
        handle = tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False)
        handle.write(parameters.parameter_bytes(
            serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3))
        handle.close()
        _dh_param_files[bits] = handle.name
    return _dh_param_files[bits]


class Handshake:
    """Our client and an OpenSSL server, pumped by hand over memory BIOs."""

    def __init__(self, *, key=None, certificate=None, ciphers="AES128-SHA:@SECLEVEL=0",
                 server_max=ssl.TLSVersion.TLSv1_2, server_ecdh_curve=None,
                 server_min=ssl.TLSVersion.TLSv1_2, roots_pem=None,
                 server_no_etm=False, server_dh_bits=None,
                 server_takes_client_order=False, **client_options):
        if certificate is None:
            key, certificate = make_server_cert()
        self.cert_pem, cert_path, key_path = pem_files(key, certificate)
        self._paths = (cert_path, key_path)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # The ciphers come first: @SECLEVEL=0 is what lets a small key or a
        # weak suite be loaded at all, and load_cert_chain checks the key
        # against the level that is set at the time.
        if ciphers:
            context.set_ciphers(ciphers)
        if server_no_etm:
            # RFC 7366 is negotiated, so the way to test the
            # MAC-then-encrypt path is to have the server decline it. The
            # option has to be set before the connection is wrapped.
            context.options |= getattr(ssl, "OP_NO_ENCRYPT_THEN_MAC", 0)
        context.load_cert_chain(cert_path, key_path)
        context.minimum_version = server_min
        context.maximum_version = server_max
        if server_takes_client_order:
            # Python turns on SSL_OP_CIPHER_SERVER_PREFERENCE for server
            # contexts, so by default the server's list decides and the
            # client's order proves nothing. Clearing it hands the choice
            # back to the client, which is the only way to test what our
            # preference order actually does.
            context.options &= ~ssl.OP_CIPHER_SERVER_PREFERENCE
        if server_dh_bits:
            # Without this OpenSSL picks its own group for DHE, and which
            # one depends on the build - so the size a test is about would
            # be whatever the library felt like.
            context.load_dh_params(dh_params_file(server_dh_bits))
        if server_ecdh_curve:
            # Pins the server to one curve, so a test can assert on which
            # one was negotiated instead of on whatever OpenSSL happens to
            # prefer this release.
            context.set_ecdh_curve(server_ecdh_curve)

        self.server_in, self.server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.server = context.wrap_bio(self.server_in, self.server_out,
                                       server_side=True)

        self.roots = allcrypt.TrustStore()
        self.roots.add_pem(roots_pem if roots_pem is not None else self.cert_pem)

        options = dict(now=NOW)
        options.update(client_options)
        hostname = options.pop("hostname", "localhost")
        self.client = allcrypt.TlsClient(hostname, self.roots, **options)

        self.server_error = None
        self.client_error = None

    def cleanup(self):
        for path in self._paths:
            try:
                os.unlink(path)
            except OSError:
                pass

    def pump(self, rounds=20):
        """Run the handshake to completion, or until something fails."""
        for _ in range(rounds):
            data = self.client.take_outgoing()
            if data:
                self.server_in.write(data)

            try:
                self.server.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            except ssl.SSLError as reason:
                self.server_error = reason

            data = self.server_out.read()
            if data:
                self.client.push_incoming(data)

            try:
                self.client.process()
            except allcrypt.CryptoError as reason:
                self.client_error = reason
                return self

            if self.client.established:
                return self
            if self.server_error and not data:
                return self
        return self

    def send(self, data):
        self.client.write(data)
        self.server_in.write(self.client.take_outgoing())
        return self.server.read(len(data) + 64)

    def receive(self, data):
        self.server.write(data)
        self.client.push_incoming(self.server_out.read())
        self.client.process()
        return self.client.take_incoming()


@pytest.fixture
def handshake():
    made = []

    def build(**options):
        exchange = Handshake(**options)
        made.append(exchange)
        return exchange

    yield build
    for exchange in made:
        exchange.cleanup()


# --------------------------------------------------------------- it works ---

def test_a_complete_handshake(handshake):
    """Our record layer, key schedule, certificate verification, state
    machine and RSA key exchange, against a real server."""
    exchange = handshake().pump()

    assert exchange.client_error is None, f"client failed: {exchange.client_error}"
    assert exchange.client.established, f"state is {exchange.client.state}"

    assert exchange.client.version() == "TLSv1.2"
    name, strength, bits = exchange.client.cipher()
    assert name == "TLS_RSA_WITH_AES_128_CBC_SHA"
    assert strength == "weak"       # CBC with SHA-1, and honest about it
    assert bits == 128

    assert exchange.client.certificate_verified
    # Both modern CBC protections, negotiated without being asked twice.
    assert exchange.client.encrypt_then_mac
    assert exchange.client.extended_master_secret

    # And the chain the server sent is readable through our own X.509 code.
    chain = exchange.client.peer_certificates
    assert len(chain) == 1
    certificate = allcrypt.Certificate(chain[0])
    assert certificate.to_dict()["commonName"] == "localhost"


def test_application_data_in_both_directions(handshake):
    exchange = handshake().pump()
    assert exchange.client.established

    assert exchange.send(b"hello from allcrypt") == b"hello from allcrypt"
    assert exchange.receive(b"hello from openssl") == b"hello from openssl"

    # Several records in a row, so the sequence numbers advance on both
    # sides. A sequence number that does not advance in step fails here.
    for index in range(5):
        message = f"message {index}".encode()
        assert exchange.send(message) == message


def test_a_large_payload_is_fragmented_and_reassembled(handshake):
    """Larger than 2^14, so the record layer has to fragment it and the
    server has to put it back together."""
    exchange = handshake().pump()
    assert exchange.client.established

    payload = bytes((i * 167 + 13) & 0xff for i in range(40000))
    exchange.client.write(payload)
    exchange.server_in.write(exchange.client.take_outgoing())

    received = b""
    while len(received) < len(payload):
        chunk = exchange.server.read(len(payload))
        if not chunk:
            break
        received += chunk
    assert received == payload


def test_aes_256(handshake):
    exchange = handshake(ciphers="AES256-SHA:@SECLEVEL=0").pump()
    assert exchange.client.established, f"{exchange.client_error}"
    assert exchange.client.cipher()[0] == "TLS_RSA_WITH_AES_256_CBC_SHA"
    assert exchange.send(b"aes256") == b"aes256"


@pytest.mark.parametrize("server_version,expected", [
    (ssl.TLSVersion.TLSv1, "TLSv1"),
    (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
    (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
])
def test_an_old_server_is_reached_with_the_ceiling_left_at_1_3(
        handshake, server_version, expected):
    """A client offering 1.3 must still come down to 1.0.

    **RFC 8446 4.2.1**: a client sending `supported_versions` lists
    "all versions of TLS which they are prepared to negotiate", and
    **4.1.2**: a server that sees the extension ignores
    `legacy_version` entirely. So the list is the whole offer, and one
    stopping at 1.2 is a client saying it cannot speak TLS 1.0.

    It used to stop at 1.2. Nothing here saw it, because every version
    test pinned `max_version` to the version under test, which puts the
    ceiling below 1.3 and skips the extension altogether. It surfaced
    from the proxy, where the ceiling is high (a modern box should get
    1.3) and the floor is low (an old one should still be reachable) -
    which is the only configuration that can tell.

    The failure is the shape that hides longest: an OpenSSL old enough
    to ignore the extension negotiates from the version field and works,
    while a current one honours it and answers `protocol_version`.
    """
    exchange = handshake(ciphers="AES128-SHA:@SECLEVEL=0",
                         server_min=server_version, server_max=server_version,
                         min_version="TLSv1", max_version="TLSv1.3").pump()

    assert exchange.client_error is None, f"{exchange.client_error}"
    assert exchange.client.established, exchange.client.state
    assert exchange.client.version() == expected
    assert exchange.send(b"reached it") == b"reached it"


def test_without_encrypt_then_mac(handshake):
    """The MAC-then-encrypt path, which is the one Lucky 13 applies to.

    This used to try to make the *server* decline RFC 7366 with
    `OP_NO_ENCRYPT_THEN_MAC`, and skipped when that constant was missing -
    which it is on this Python. So the single most delicate path in the
    record layer had no coverage at all here, and the skip made that look
    like a property of the environment rather than a hole.

    Not offering the extension is a client-side decision, so it is one now:
    `request_encrypt_then_mac=False`. That is also a real capability rather
    than a test hook - some old equipment mishandles the extension, and
    reaching it means being able to stop sending it.
    """
    exchange = handshake(ciphers="AES128-SHA:@SECLEVEL=0",
                         request_encrypt_then_mac=False).pump()

    assert exchange.client.established, f"{exchange.client_error}"
    assert not exchange.client.encrypt_then_mac, (
        "encrypt-then-MAC was negotiated even though it was not offered")
    assert exchange.send(b"mac then encrypt") == b"mac then encrypt"
    assert exchange.receive(b"and back again") == b"and back again"

    # Several records, because the padding and the MAC are per record and
    # the first one is the easiest to get right by accident.
    for index in range(8):
        message = bytes([index]) * (index * 7 + 1)
        assert exchange.send(message) == message


def test_closing_cleanly(handshake):
    exchange = handshake().pump()
    assert exchange.client.established

    exchange.client.close()
    exchange.server_in.write(exchange.client.take_outgoing())
    assert exchange.server.read(10) == b""      # close_notify seen as EOF
    assert exchange.client.state == "Closed"


# ------------------------------------------------------ it refuses to work ---

def test_an_untrusted_certificate_is_refused(handshake):
    """The test that makes every other one mean something: a server whose
    certificate we do not trust must not get a connection."""
    _, other = make_server_cert()
    other_pem = other.public_bytes(serialization.Encoding.PEM).decode()

    exchange = handshake(roots_pem=other_pem).pump()
    assert not exchange.client.established
    assert exchange.client_error is not None
    assert "unknown_ca" in str(exchange.client_error).lower() \
        or "trusted root" in str(exchange.client_error)


def test_the_wrong_hostname_is_refused(handshake):
    exchange = handshake(hostname="not-the-server.test").pump()
    assert not exchange.client.established
    assert "does not cover" in str(exchange.client_error)


def test_an_expired_certificate_is_refused(handshake):
    key, certificate = make_server_cert()
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()

    # The certificate is valid now; the client's clock is not.
    exchange = handshake(key=key, certificate=certificate, roots_pem=cert_pem)
    exchange.client = allcrypt.TlsClient(
        "localhost", exchange.roots,
        now=int(datetime.datetime(2050, 1, 1,
                                  tzinfo=datetime.timezone.utc).timestamp()))
    exchange.pump()

    assert not exchange.client.established
    assert "Expired" in str(exchange.client_error)


def test_a_small_rsa_key_is_refused_by_default(handshake):
    """1024 bits is factorable by somebody with resources. Refused unless
    asked for - and talking to old things is the point, so it can be."""
    key, certificate = make_server_cert(key_size=1024)
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()

    exchange = handshake(key=key, certificate=certificate, roots_pem=cert_pem,
                         ciphers="AES128-SHA:@SECLEVEL=0").pump()
    assert not exchange.client.established
    assert "1024" in str(exchange.client_error)

    # And with the floor lowered deliberately, it connects.
    again = handshake(key=key, certificate=certificate, roots_pem=cert_pem,
                      ciphers="AES128-SHA:@SECLEVEL=0", min_rsa_bits=1024).pump()
    assert again.client.established, f"{again.client_error}"
    assert again.send(b"old key") == b"old key"


# ------------------------------------------------- reaching something old ---
#
# Four ways to accept a certificate the default policy refuses, from the
# narrowest to the widest. The order matters: each one relaxes strictly
# more than the last, and a caller should reach for the first that works
# rather than the one that always works.


def test_a_pinned_certificate_is_the_narrowest_answer(handshake):
    """Put the server's own certificate in the trust store.

    This is not a relaxation at all - it is authentication, done properly,
    against a certificate you chose. For a box with a self-signed
    certificate it is strictly better than turning verification off: a
    man in the middle still fails, because it does not have that key.

    Every handshake test in this file already does it, which is why it is
    worth naming: the thing people reach for `verify=False` to do is
    usually this.
    """
    exchange = handshake().pump()
    assert exchange.client.established
    assert exchange.client.certificate_verified

    # And a *different* self-signed certificate is still refused, which is
    # what makes this authentication rather than a shrug.
    _key, other = make_server_cert()
    other_pem = other.public_bytes(serialization.Encoding.PEM).decode()
    refused = handshake(roots_pem=other_pem).pump()
    assert not refused.client.established


@pytest.mark.parametrize("days_expired", [1, 400, 4000])
def test_allow_expired_relaxes_the_dates_and_nothing_else(handshake,
                                                          days_expired):
    """A certificate that ran out years ago, on a box nobody will reissue
    for. The single most common reason old equipment is unreachable.

    What this must NOT do is become a general "accept anything": the
    chain, the signatures and the name are all still checked, and the
    second half of this test is what says so.
    """
    key, certificate = make_server_cert(not_after_days=-days_expired)
    exchange = handshake(key=key, certificate=certificate).pump()
    assert not exchange.client.established, "an expired certificate was accepted"
    assert "xpired" in str(exchange.client_error)

    allowed = handshake(key=key, certificate=certificate,
                        allow_expired=True).pump()
    assert allowed.client_error is None, f"{allowed.client_error}"
    assert allowed.client.established
    assert allowed.client.certificate_verified

    # Still authenticated: an expired certificate from somewhere else is
    # not accepted just because expiry is forgiven.
    _other_key, other = make_server_cert(common_name="somewhere.else",
                                         sans=("somewhere.else",))
    other_pem = other.public_bytes(serialization.Encoding.PEM).decode()
    elsewhere = handshake(key=key, certificate=certificate,
                          roots_pem=other_pem, allow_expired=True).pump()
    assert not elsewhere.client.established, \
        "allow_expired stopped checking the chain"


def test_verify_hostname_can_be_turned_off_on_its_own(handshake):
    """"A certificate I trust, for a name I am not checking."

    What you want when connecting to a box by IP address, or to one whose
    certificate was issued for a name it no longer answers to. Much
    narrower than turning verification off, and until now impossible: the
    hostname check was welded to the chain check, so the Python shim's
    `check_hostname = False` was silently ignored by our own stack.
    """
    exchange = handshake(hostname="not-the-name-on-it").pump()
    assert not exchange.client.established
    assert "does not cover" in str(exchange.client_error)

    allowed = handshake(hostname="not-the-name-on-it",
                        verify_hostname=False).pump()
    assert allowed.client_error is None, f"{allowed.client_error}"
    assert allowed.client.established
    # The chain was still verified - that is the entire distinction.
    assert allowed.client.certificate_verified

    # And a certificate from an untrusted issuer is still refused, so this
    # really is only about the name.
    _other_key, other = make_server_cert(common_name="somewhere.else",
                                         sans=("somewhere.else",))
    other_pem = other.public_bytes(serialization.Encoding.PEM).decode()
    untrusted = handshake(hostname="not-the-name-on-it",
                          verify_hostname=False, roots_pem=other_pem).pump()
    assert not untrusted.client.established, \
        "verify_hostname=False stopped checking the chain"


def test_verification_can_be_turned_off_deliberately(handshake):
    """Sometimes it is the only way to talk to something. It is a named
    argument, and the connection reports it afterwards, so it cannot be on
    by accident."""
    _, other = make_server_cert()
    other_pem = other.public_bytes(serialization.Encoding.PEM).decode()

    exchange = handshake(roots_pem=other_pem, verify=False).pump()
    assert exchange.client.established, f"{exchange.client_error}"
    assert not exchange.client.certificate_verified
    assert exchange.send(b"unverified") == b"unverified"

    # The certificate is still available to look at, which is the point of
    # not verifying rather than not caring.
    assert len(exchange.client.peer_certificates) == 1


def test_a_server_that_offers_nothing_we_accept(handshake):
    """The server only speaks RC4, which the default selection does not
    offer. The handshake must fail rather than quietly downgrade."""
    try:
        exchange = handshake(ciphers="RC4-SHA:@SECLEVEL=0").pump()
    except ssl.SSLError:
        pytest.skip("this OpenSSL cannot be made to offer RC4")
    assert not exchange.client.established


def test_a_version_we_did_not_offer(handshake):
    """A server pinned to TLS 1.0 while we offer only 1.2."""
    exchange = handshake(server_min=ssl.TLSVersion.TLSv1,
                         server_max=ssl.TLSVersion.TLSv1,
                         ciphers="AES128-SHA:@SECLEVEL=0").pump()
    assert not exchange.client.established


def test_a_failure_is_sticky(handshake):
    exchange = handshake(hostname="wrong.test").pump()
    assert exchange.client_error is not None
    assert exchange.client.state == "Failed"

    # Nothing brings it back, and writing is refused.
    with pytest.raises(allcrypt.CryptoError):
        exchange.client.write(b"anything")


def test_the_client_needs_roots_or_a_decision():
    empty = allcrypt.TrustStore()
    with pytest.raises(allcrypt.CryptoError) as info:
        allcrypt.TlsClient("localhost", empty, now=NOW)
    assert "no trusted roots" in str(info.value)

    # Unless verification is off, which is a decision.
    client = allcrypt.TlsClient("localhost", empty, now=NOW, verify=False)
    assert not client.established


def test_garbage_does_not_crash():
    roots = allcrypt.TrustStore()
    _, certificate = make_server_cert()
    roots.add_pem(certificate.public_bytes(serialization.Encoding.PEM).decode())

    for seed in range(50):
        client = allcrypt.TlsClient("localhost", roots, now=NOW)
        client.take_outgoing()
        client.push_incoming(bytes((i * 37 + seed * 11) & 0xff for i in range(300)))
        try:
            client.process()
        except allcrypt.CryptoError:
            pass


# ------------------------------------------------------------------ ECDHE ---
#
# Everything above this line uses a static RSA key exchange, which no server
# built this decade will do. ECDHE is how you reach anything current, and it
# adds a piece nothing else in the library exercises end to end: a signature,
# made by the server over its ephemeral public key, verified by us against
# the certificate. Getting that wrong in the permissive direction means the
# ephemeral key is unauthenticated - which is precisely what a man in the
# middle provides - and every happy-path test still passes.


def make_ecdsa_server_cert(curve=None, common_name="localhost",
                           sans=("localhost",)):
    """A self-signed ECDSA server certificate, for the ECDHE_ECDSA suites."""
    key = ec.generate_private_key(curve or ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(1)
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=3650))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                              critical=True)
               .add_extension(usage(digital_signature=True, key_cert_sign=True,
                                    crl_sign=True), critical=True)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                              critical=False))
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]),
            critical=False)
    return key, builder.sign(key, hashes.SHA256())


ECDHE_RSA_SUITES = [
    ("ECDHE-RSA-AES128-SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 128),
    ("ECDHE-RSA-AES256-SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 256),
    ("ECDHE-RSA-AES128-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 128),
    ("ECDHE-RSA-AES256-SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 256),
]


@pytest.mark.parametrize("openssl_name,our_name,bits", ECDHE_RSA_SUITES)
def test_ecdhe_rsa_suites(handshake, openssl_name, our_name, bits):
    """Each ECDHE_RSA suite we implement, against OpenSSL.

    The SHA256 and SHA384 ones are not just a different MAC: in TLS 1.2 the
    PRF hash is part of the suite, so AES256-SHA384 derives its master
    secret, key block and Finished with SHA-384. A stack that hardcodes
    SHA-256 anywhere in that path passes the first two rows here and fails
    the last one.
    """
    exchange = handshake(ciphers=f"{openssl_name}:@SECLEVEL=0").pump()

    assert exchange.client_error is None, f"client failed: {exchange.client_error}"
    assert exchange.client.established, f"state is {exchange.client.state}"

    name, _strength, key_bits = exchange.client.cipher()
    assert name == our_name
    assert key_bits == bits
    assert exchange.client.certificate_verified
    assert exchange.client.named_group is not None

    # And the connection carries data, which is the real proof that both
    # sides derived the same keys from the shared secret.
    assert exchange.send(b"over ECDHE") == b"over ECDHE"
    assert exchange.receive(b"and back") == b"and back"


@pytest.mark.parametrize("openssl_name,our_name", [
    ("ECDHE-ECDSA-AES128-SHA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
    ("ECDHE-ECDSA-AES256-SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
])
def test_ecdhe_ecdsa_suites(handshake, openssl_name, our_name):
    """ECDHE with an ECDSA certificate: our ECDSA *verification* against
    signatures OpenSSL produced, in both the ServerKeyExchange and the
    certificate's own self-signature."""
    key, certificate = make_ecdsa_server_cert()
    exchange = handshake(key=key, certificate=certificate,
                         ciphers=f"{openssl_name}:@SECLEVEL=0").pump()

    assert exchange.client_error is None, f"client failed: {exchange.client_error}"
    assert exchange.client.established
    assert exchange.client.cipher()[0] == our_name
    assert exchange.client.certificate_verified
    assert exchange.send(b"ecdsa") == b"ecdsa"


def test_a_p521_certificate_signs_the_key_exchange(handshake):
    """A server whose only curve is P-521, certificate and exchange both.

    66 byte field elements: a ServerKeyExchange point of 133 bytes and an
    ECDSA signature whose r and s may each be one byte shorter than the
    field - the width that `bits / 8` gets wrong, checked here against
    OpenSSL's encoder rather than ours."""
    key, certificate = make_ecdsa_server_cert(ec.SECP521R1())
    exchange = handshake(key=key, certificate=certificate,
                         ciphers="ECDHE-ECDSA-AES256-GCM-SHA384:@SECLEVEL=0",
                         server_ecdh_curve="secp521r1").pump()
    assert exchange.client_error is None, f"client failed: {exchange.client_error}"
    assert exchange.client.established
    assert exchange.client.certificate_verified
    assert exchange.client.named_group == "secp521r1"
    assert exchange.send(b"over P-521") == b"over P-521"


@pytest.mark.parametrize("curve,expected", [
    ("prime256v1", "secp256r1"),
    ("secp384r1", "secp384r1"),
    ("secp521r1", "secp521r1"),
    ("X25519", "x25519"),
])
def test_the_negotiated_curve_is_the_one_the_server_chose(handshake, curve,
                                                          expected):
    """We offer a list; the server picks one. Reporting the curve we would
    have preferred rather than the one in the ServerKeyExchange would be a
    lie that only shows up when it matters."""
    exchange = handshake(ciphers="ECDHE-RSA-AES128-SHA:@SECLEVEL=0",
                         server_ecdh_curve=curve).pump()
    assert exchange.client_error is None, f"client failed: {exchange.client_error}"
    assert exchange.client.established
    assert exchange.client.named_group == expected


def test_an_x25519_key_of_the_wrong_length_is_refused(handshake):
    """The one thing that can be wrong about an X25519 public key is its
    length - every 32 byte string is a valid u coordinate. A client that
    accepts a short one either pads it silently or indexes past it."""
    exchange = handshake(ciphers="ECDHE-RSA-AES128-SHA:@SECLEVEL=0",
                         server_ecdh_curve="X25519")

    exchange.server_in.write(exchange.client.take_outgoing())
    try:
        exchange.server.do_handshake()
    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
        pass
    flight = exchange.server_out.read()
    assert flight

    exchange.client.push_incoming(truncate_the_ecdh_point(flight))
    with pytest.raises(allcrypt.CryptoError) as info:
        exchange.client.process()
    assert not exchange.client.established
    # Either the length check or the signature check may fire first; both
    # are refusals for a real reason, and neither is "it worked".
    assert ("32 bytes" in str(info.value)
            or "signature" in str(info.value).lower()), info.value


def test_a_tampered_server_key_exchange_is_refused(handshake):
    """The check that makes ephemeral key exchange mean anything.

    The signature over the server's ephemeral public key is the only thing
    binding that key to the certificate. Without it, anyone in the path
    substitutes their own key and reads everything, and the handshake still
    completes - so this must fail, and it must fail for the right reason.

    One bit is flipped in the signature, in the server's own first flight,
    which is the weakest possible tampering. A verifier that is broken in
    the permissive direction usually accepts far more than this.
    """
    exchange = handshake(ciphers="ECDHE-RSA-AES128-SHA:@SECLEVEL=0")

    # Drive the handshake by hand as far as the server's first flight, then
    # corrupt it on the way in.
    exchange.server_in.write(exchange.client.take_outgoing())
    try:
        exchange.server.do_handshake()
    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
        pass
    flight = exchange.server_out.read()
    assert flight, "the server should have sent its first flight"

    tampered = flip_a_bit_in_server_key_exchange(flight)
    assert tampered != flight, "the flight should contain a ServerKeyExchange"

    exchange.client.push_incoming(tampered)
    with pytest.raises(allcrypt.CryptoError) as info:
        exchange.client.process()
    assert "signature" in str(info.value).lower(), info.value
    assert not exchange.client.established


# --------------------------------------------------------------- versions ---
#
# TLS 1.0 and 1.1, which is what most of the equipment this library exists
# for actually speaks. The record layer has had the two constructions since
# it was written and neither had ever been driven at those versions against
# a real server - they are genuinely different code paths, not a version
# number in a header:
#
#   * TLS 1.0 chains the CBC IV from the previous record. TLS 1.1 sends a
#     fresh explicit IV with each one, which is what fixed BEAST.
#   * Before 1.2 the PRF is MD5 and SHA-1 over split halves of the secret,
#     and the transcript hash for Finished is MD5 || SHA-1 rather than the
#     suite's hash.


LEGACY_VERSIONS = [
    (ssl.TLSVersion.TLSv1, "TLSv1"),
    (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
    (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
]


@pytest.mark.parametrize("server_version,our_name", LEGACY_VERSIONS)
@pytest.mark.parametrize("etm", [False, True])
def test_every_version_we_speak(handshake, server_version, our_name, etm):
    """A complete handshake at each version, with and without RFC 7366.

    Four combinations of record construction across the two axes, and the
    chained-IV one has to be exercised over several records: record N's IV
    is record N-1's last ciphertext block, so a single record cannot tell
    a chained IV from a fixed one.
    """
    exchange = handshake(ciphers="AES128-SHA:@SECLEVEL=0",
                         server_min=server_version, server_max=server_version,
                         request_encrypt_then_mac=etm,
                         min_version="TLSv1", max_version=our_name).pump()

    assert exchange.client_error is None, f"client failed: {exchange.client_error}"
    assert exchange.client.established, f"state is {exchange.client.state}"
    assert exchange.client.version() == our_name
    assert exchange.client.certificate_verified
    assert exchange.client.encrypt_then_mac == etm, (
        "the server's encrypt-then-MAC answer was not honoured")

    # Several records each way. The first is never enough for a chained IV.
    for index in range(8):
        message = f"record {index} at {our_name}".encode() * (index + 1)
        assert exchange.send(message) == message
        assert exchange.receive(message) == message


@pytest.mark.parametrize("server_version,our_name", LEGACY_VERSIONS)
def test_a_large_payload_at_every_version(handshake, server_version, our_name):
    """Past 2^14 the payload spans records, which for TLS 1.0 means the
    chained IV really does have to carry from one to the next."""
    exchange = handshake(ciphers="AES256-SHA:@SECLEVEL=0",
                         server_min=server_version, server_max=server_version,
                         min_version="TLSv1", max_version=our_name).pump()
    assert exchange.client_error is None, f"client failed: {exchange.client_error}"

    payload = bytes((i * 11 + 5) & 0xff for i in range(40000))
    exchange.client.write(payload)
    exchange.server_in.write(exchange.client.take_outgoing())
    received = b""
    while len(received) < len(payload):
        received += exchange.server.read(len(payload) - len(received) + 64)
    assert received == payload


@pytest.mark.parametrize("server_version,our_name", LEGACY_VERSIONS)
@pytest.mark.parametrize("openssl_name,cert", [
    ("ECDHE-RSA-AES128-SHA", "rsa"),
    ("ECDHE-RSA-AES256-SHA", "rsa"),
    ("ECDHE-ECDSA-AES128-SHA", "ecdsa"),
])
def test_ephemeral_key_exchange_at_every_version(handshake, server_version,
                                                 our_name, openssl_name, cert):
    """ECDHE at TLS 1.0 and 1.1, which is what old equipment actually offers.

    This is the gap that let two real bugs through, and the reason it was a
    gap is exact: every other version test above uses a **static RSA** key
    exchange, which has no ServerKeyExchange at all - so nothing ever
    signed anything, and the whole pre-1.2 signature path was unreached.
    A real TLS 1.0 server found both.

    What differs before TLS 1.2, for an RSA signature:

      * the digest is `MD5(input) || SHA1(input)`, 36 bytes, both hashes
        concatenated - not a single named hash;
      * it is signed with **no DigestInfo prefix**, because there is no
        algorithm to identify: the pair is fixed by the protocol version;
      * there is no SignatureAndHashAlgorithm in the message, so the weak
        hash policy has nothing to apply to. Applying it anyway refused
        every TLS 1.0 and 1.1 ephemeral handshake, which is most of what
        the servers this library exists for offer.

    ECDSA is the control: before 1.2 it signs SHA-1 alone with no prefix,
    which is what the code already did - so ECDSA worked at TLS 1.0 while
    RSA did not, and a test covering only one of them proves nothing about
    the other.
    """
    key = certificate = None
    if cert == "ecdsa":
        key, certificate = make_ecdsa_server_cert()

    exchange = handshake(key=key, certificate=certificate,
                         ciphers=f"{openssl_name}:@SECLEVEL=0",
                         server_min=server_version, server_max=server_version,
                         min_version="TLSv1", max_version=our_name).pump()

    assert exchange.client_error is None, f"client failed: {exchange.client_error}"
    assert exchange.client.established, f"state is {exchange.client.state}"
    assert exchange.client.version() == our_name
    assert exchange.client.certificate_verified
    assert exchange.client.named_group is not None

    assert exchange.send(b"ephemeral") == b"ephemeral"
    assert exchange.receive(b"and back") == b"and back"


@pytest.mark.parametrize("server_version,our_name", [
    (ssl.TLSVersion.TLSv1, "TLSv1"),
    (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
])
def test_a_forged_pre_tls12_key_exchange_is_still_refused(handshake,
                                                          server_version,
                                                          our_name):
    """The pre-1.2 signature path must still be a real check.

    Relaxing the weak-hash policy for TLS 1.0 and 1.1 is not relaxing the
    signature. If the fix had gone one step further and skipped
    verification along with the policy, every test above would still pass
    and the ephemeral key would be unauthenticated - which is the whole
    thing the signature exists to prevent.
    """
    exchange = handshake(ciphers="ECDHE-RSA-AES128-SHA:@SECLEVEL=0",
                         server_min=server_version, server_max=server_version,
                         min_version="TLSv1", max_version=our_name)

    exchange.server_in.write(exchange.client.take_outgoing())
    try:
        exchange.server.do_handshake()
    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
        pass
    flight = exchange.server_out.read()
    assert flight

    tampered = flip_a_bit_in_server_key_exchange(flight)
    assert tampered != flight, "the flight should contain a ServerKeyExchange"

    exchange.client.push_incoming(tampered)
    with pytest.raises(allcrypt.CryptoError) as info:
        exchange.client.process()
    assert "signature" in str(info.value).lower(), info.value
    assert not exchange.client.established


@pytest.mark.parametrize("server_version,our_name", LEGACY_VERSIONS)
def test_x25519_at_every_version(handshake, server_version, our_name):
    """X25519 is a different shape from the other curves, not a different
    parameter set: a Montgomery ladder on one coordinate, little-endian
    throughout where everything else here is big-endian, and a scalar that
    must be clamped. Each of those is a way to build something that agrees
    with itself and with nobody - which is why the arithmetic is pinned to
    the RFC 7748 vectors in the unit tests and the wire format is pinned
    here, against OpenSSL.
    """
    exchange = handshake(ciphers="ECDHE-RSA-AES128-SHA:@SECLEVEL=0",
                         server_ecdh_curve="X25519",
                         server_min=server_version, server_max=server_version,
                         min_version="TLSv1", max_version=our_name).pump()

    assert exchange.client_error is None, f"client failed: {exchange.client_error}"
    assert exchange.client.established
    assert exchange.client.named_group == "x25519"
    assert exchange.send(b"montgomery") == b"montgomery"
    assert exchange.receive(b"and back") == b"and back"


# ------------------------------------------- finite-field Diffie-Hellman ---
#
# DHE is what a server offers when it is too old for elliptic curves, and
# it is the key exchange where the *server* picks the group. The client's
# only say is to accept it or hang up, which is why the size floor below
# is a real defence rather than a formality.


@pytest.mark.parametrize("server_version,our_name", LEGACY_VERSIONS)
def test_finite_field_dhe_at_every_version(handshake, server_version, our_name):
    """DHE-RSA at TLS 1.0, 1.1 and 1.2 with a 2048 bit group.

    A completed handshake here is a stronger statement than it looks. Both
    sides derived the same premaster, which means our modular
    exponentiation, our padding of the public value on the wire, and the
    RFC 5246 section 8.1.2 rule that strips leading zeros from the shared
    secret all match OpenSSL's. Get any one of them wrong and the Finished
    messages disagree.
    """
    exchange = handshake(ciphers="DHE-RSA-AES128-SHA:@SECLEVEL=0",
                         server_dh_bits=2048,
                         server_min=server_version, server_max=server_version,
                         min_version="TLSv1", max_version=our_name).pump()

    assert exchange.client_error is None, f"client failed: {exchange.client_error}"
    assert exchange.client.established, f"state is {exchange.client.state}"
    assert exchange.client.version() == our_name
    assert exchange.client.cipher()[0].startswith("TLS_DHE_RSA_")
    assert exchange.client.named_group == "dh2048"
    assert exchange.client.certificate_verified

    assert exchange.send(b"finite field") == b"finite field"
    assert exchange.receive(b"and back") == b"and back"


@pytest.mark.parametrize("openssl_name,expected_tag", [
    ("DHE-RSA-AES128-CCM", 16),
    ("DHE-RSA-AES256-CCM", 16),
    ("DHE-RSA-AES128-CCM8", 8),
    ("DHE-RSA-AES256-CCM8", 8),
])
def test_aes_ccm_suites(handshake, openssl_name, expected_tag):
    """AES-CCM (RFC 6655): the same cipher, a different AEAD - CBC-MAC and
    CTR rather than GHASH, which is what hardware without a carryless
    multiply can do cheaply.

    The CCM_8 rows are the ones worth having separately. Their tag is
    eight bytes, and a record layer that assumed sixteen would read the
    last eight bytes of every ciphertext as part of the tag - which fails
    in a way that looks like a decryption error rather than like a length
    bug.
    """
    exchange = handshake(ciphers=f"{openssl_name}:@SECLEVEL=0",
                         server_dh_bits=2048).pump()
    assert exchange.client_error is None, f"{exchange.client_error}"
    assert exchange.client.established
    assert "CCM" in exchange.client.cipher()[0]

    # Several records each way, because a tag length that is wrong by
    # eight bytes could still let one short record through by luck.
    for index in range(5):
        payload = bytes([index]) * (index * 37 + 1)
        assert exchange.send(payload) == payload
        assert exchange.receive(payload) == payload


@pytest.mark.parametrize("openssl_name", [
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES256-SHA256",
])
def test_dhe_with_each_bulk_cipher(handshake, openssl_name):
    """The key exchange is independent of the record protection, but
    "independent" is a claim about code that has to be run: the AEAD path
    and the CBC path reach the key schedule by different routes."""
    exchange = handshake(ciphers=f"{openssl_name}:@SECLEVEL=0",
                         server_dh_bits=2048).pump()
    assert exchange.client_error is None, f"{exchange.client_error}"
    assert exchange.client.established
    assert exchange.send(b"either way") == b"either way"


def test_a_small_dh_group_is_refused_by_default(handshake):
    """Logjam, in the form the client can actually do something about.

    A 1024 bit group is not broken on a laptop, but it is the size the
    precomputation attack was written about, and the server offers it
    without asking. The default refuses; lowering the floor reaches it
    anyway, which is the whole point of this library.
    """
    refused = handshake(ciphers="DHE-RSA-AES128-SHA:@SECLEVEL=0",
                        server_dh_bits=1024).pump()
    assert not refused.client.established, "a 1024 bit group was accepted"
    assert "1024" in str(refused.client_error), refused.client_error

    allowed = handshake(ciphers="DHE-RSA-AES128-SHA:@SECLEVEL=0",
                        server_dh_bits=1024, min_dh_bits=1024).pump()
    assert allowed.client_error is None, f"{allowed.client_error}"
    assert allowed.client.established
    assert allowed.client.named_group == "dh1024"

    # And the floor is a floor, not a fixed list of sizes: a group larger
    # than the minimum is fine.
    bigger = handshake(ciphers="DHE-RSA-AES128-SHA:@SECLEVEL=0",
                       server_dh_bits=2048, min_dh_bits=1024).pump()
    assert bigger.client.established


def test_the_dh_prime_check_is_available_and_passes_on_a_real_group(handshake):
    """A composite modulus makes the shared secret computable by whoever
    chose it, and nothing else in the handshake notices: the arithmetic
    works and the signature over the parameters verifies, because the
    server signed the parameters and the server is the problem.

    OpenSSL will not serve a composite modulus, so what this test can
    check end to end is that the check is reachable, costs a handshake
    nothing in correctness, and passes on a real group. The composite case
    is covered in the Rust unit tests, where the modulus can be chosen.
    """
    exchange = handshake(ciphers="DHE-RSA-AES128-SHA:@SECLEVEL=0",
                         server_dh_bits=2048, check_dh_prime=True).pump()
    assert exchange.client_error is None, f"{exchange.client_error}"
    assert exchange.client.established


def test_a_tampered_dh_key_exchange_is_refused(handshake):
    """The signature over ServerDHParams is the only thing tying the group
    and the server's public value to the certificate. Without it an active
    attacker substitutes its own group - a small one, or one with a
    trapdoor - and both sides complete the handshake happily."""
    exchange = handshake(ciphers="DHE-RSA-AES128-SHA:@SECLEVEL=0",
                         server_dh_bits=2048)

    exchange.server_in.write(exchange.client.take_outgoing())
    try:
        exchange.server.do_handshake()
    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
        pass
    flight = exchange.server_out.read()
    assert flight

    tampered = flip_a_bit_in_server_key_exchange(flight)
    assert tampered != flight, "the flight should contain a ServerKeyExchange"

    exchange.client.push_incoming(tampered)
    with pytest.raises(allcrypt.CryptoError) as info:
        exchange.client.process()
    assert "signature" in str(info.value).lower(), info.value
    assert not exchange.client.established


def test_the_default_selection_prefers_the_curve_over_the_field(handshake):
    """Both are offered, and a server that will do either should get
    ECDHE: it is faster, and its group is a name we recognise rather than
    numbers we have to take on trust."""
    exchange = handshake(ciphers="DHE-RSA-AES128-GCM-SHA256:"
                                 "ECDHE-RSA-AES128-GCM-SHA256",
                         server_dh_bits=2048,
                         server_takes_client_order=True).pump()
    assert exchange.client.established
    assert exchange.client.cipher()[0].startswith("TLS_ECDHE_"), \
        exchange.client.cipher()[0]


def test_the_version_floor_is_honoured(handshake):
    """A client that will not go below 1.2 must refuse a 1.0 server, even
    though it can speak 1.0. The floor is a decision, not a capability."""
    exchange = handshake(ciphers="AES128-SHA:@SECLEVEL=0",
                         server_min=ssl.TLSVersion.TLSv1,
                         server_max=ssl.TLSVersion.TLSv1,
                         min_version="TLSv1.2", max_version="TLSv1.2").pump()
    assert not exchange.client.established
    assert exchange.client_error is not None


# ------------------------------------------------------------------- AEAD ---
#
# The GCM suites, which is what a modern server actually prefers. The record
# construction has almost nothing in common with the CBC one: no padding, a
# nonce split between the key block and the wire, and additional data whose
# length field counts the plaintext rather than what is in the record header.


GCM_SUITES = [
    ("ECDHE-RSA-AES128-GCM-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 128),
    ("ECDHE-RSA-AES256-GCM-SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 256),
    ("AES128-GCM-SHA256", "TLS_RSA_WITH_AES_128_GCM_SHA256", 128),
    ("AES256-GCM-SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384", 256),
]


@pytest.mark.parametrize("openssl_name,our_name,bits", GCM_SUITES)
def test_gcm_suites(handshake, openssl_name, our_name, bits):
    """A full handshake and real traffic on a GCM suite, both key exchanges.

    These are the first suites here that our own registry calls `modern`
    rather than `weak`, and the first with no MAC key in the key block at
    all - the mac_len is zero, so every offset after it moves. A key block
    split that assumed a MAC key would derive keys that are wrong by 32 or
    48 bytes and fail at the Finished with nothing to say why.
    """
    exchange = handshake(ciphers=f"{openssl_name}:@SECLEVEL=0").pump()

    assert exchange.client_error is None, f"client failed: {exchange.client_error}"
    assert exchange.client.established, f"state is {exchange.client.state}"

    name, strength, key_bits = exchange.client.cipher()
    assert name == our_name
    assert key_bits == bits
    assert strength == "modern"
    assert exchange.client.certificate_verified

    # An AEAD has no separate MAC, so encrypt-then-MAC does not apply and
    # must not be reported as negotiated - RFC 7366 is for CBC suites only,
    # and a server will not send the extension back for these.
    assert not exchange.client.encrypt_then_mac

    assert exchange.send(b"over GCM") == b"over GCM"
    assert exchange.receive(b"and back") == b"and back"


@pytest.mark.parametrize("openssl_name,our_name", [
    ("ECDHE-RSA-CHACHA20-POLY1305", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
])
def test_chacha20_poly1305_suites(handshake, openssl_name, our_name):
    """RFC 7905, whose nonce is built the other way.

    GCM sends eight bytes of nonce with every record; this one sends none
    and XORs the sequence number into the key block's IV instead. Same
    additional data, same tag length, completely different derivation - so
    a record layer that got GCM right tells you nothing about this.
    """
    exchange = handshake(ciphers=f"{openssl_name}:@SECLEVEL=0").pump()

    assert exchange.client_error is None, f"client failed: {exchange.client_error}"
    assert exchange.client.established, f"state is {exchange.client.state}"

    name, strength, bits = exchange.client.cipher()
    assert name == our_name
    assert strength == "modern"
    assert bits == 256
    assert exchange.client.certificate_verified
    assert not exchange.client.encrypt_then_mac

    # Several records, because the nonce is derived from the sequence
    # number and only the second record can catch a counter that is stuck.
    for index in range(10):
        message = f"chacha record {index}".encode()
        assert exchange.send(message) == message
        assert exchange.receive(message) == message


def test_gcm_carries_many_records(handshake):
    """Several records in a row, which is where the nonce has to change.

    One record proves nothing about the nonce: it is only on the second
    that a stuck sequence number produces a repeat, and a repeated nonce in
    GCM hands over the authentication key. Both directions, because the two
    have their own counters and only one of them is ours to get wrong.
    """
    exchange = handshake(ciphers="ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0").pump()
    assert exchange.client_error is None, f"client failed: {exchange.client_error}"

    for index in range(20):
        message = f"record {index}".encode() * (index + 1)
        assert exchange.send(message) == message
        assert exchange.receive(message) == message


def test_a_large_gcm_payload_is_fragmented(handshake):
    """Past 2^14 the payload spans records, each with its own nonce and tag."""
    exchange = handshake(ciphers="ECDHE-RSA-AES256-GCM-SHA384:@SECLEVEL=0").pump()
    assert exchange.client_error is None, f"client failed: {exchange.client_error}"

    payload = bytes((i * 7 + 3) & 0xff for i in range(40000))
    exchange.client.write(payload)
    exchange.server_in.write(exchange.client.take_outgoing())
    received = b""
    while len(received) < len(payload):
        received += exchange.server.read(len(payload) - len(received) + 64)
    assert received == payload


def test_a_tampered_gcm_record_is_refused(handshake):
    """Any change at all to a protected record must fail the tag.

    Unlike the CBC path there is no padding to get wrong and no order of
    checks to hold to - the tag covers the whole record, so this is really
    a test that the additional data is built from the right bytes. Get the
    sequence number or the length field wrong and these still fail, but so
    does everything, which is why the passing cases above come first.
    """
    exchange = handshake(ciphers="ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0").pump()
    assert exchange.client_error is None, f"client failed: {exchange.client_error}"

    exchange.server.write(b"a protected message")
    record = exchange.server_out.read()
    assert record[0] == 23, "expected an application data record"

    # Flip one bit in the ciphertext, leaving the header alone.
    altered = bytearray(record)
    altered[-1] ^= 0x01
    exchange.client.push_incoming(bytes(altered))
    with pytest.raises(allcrypt.CryptoError) as info:
        exchange.client.process()
    assert "authenticate" in str(info.value).lower(), info.value

    # And the connection stays failed rather than resynchronising.
    assert not exchange.client.established


def test_a_replayed_gcm_record_is_refused(handshake):
    """The same record twice must fail the second time.

    The sequence number is in the additional data, so a record that
    authenticated at position n does not authenticate at position n+1. That
    is the only thing standing between this and a replay, and it is easy to
    leave out because nothing in a normal session ever exercises it.
    """
    exchange = handshake(ciphers="ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0").pump()
    assert exchange.client_error is None, f"client failed: {exchange.client_error}"

    exchange.server.write(b"say it once")
    record = exchange.server_out.read()

    exchange.client.push_incoming(record)
    exchange.client.process()
    assert exchange.client.take_incoming() == b"say it once"

    exchange.client.push_incoming(record)
    with pytest.raises(allcrypt.CryptoError):
        exchange.client.process()


def flip_a_bit_in_server_key_exchange(flight):
    """Flip the last bit of the signature in the ServerKeyExchange.

    The flight is plaintext at this point - the handshake has not switched
    to encryption yet - so it is a sequence of TLS records, each holding
    part of the handshake stream. The messages are found by walking the
    handshake stream rather than by searching for bytes, because a search
    for a type byte finds one inside a certificate soon enough.
    """
    records, offset = [], 0
    while offset < len(flight):
        content_type = flight[offset]
        length = int.from_bytes(flight[offset + 3:offset + 5], "big")
        body = flight[offset + 5:offset + 5 + length]
        records.append((content_type, flight[offset:offset + 3], body))
        offset += 5 + length

    stream = b"".join(body for kind, _, body in records if kind == 22)
    rebuilt, position, changed = bytearray(stream), 0, False
    while position + 4 <= len(stream):
        message_type = stream[position]
        length = int.from_bytes(stream[position + 1:position + 4], "big")
        if message_type == 12:                       # server_key_exchange
            rebuilt[position + 3 + length] ^= 0x01   # last byte of the body
            changed = True
        position += 4 + length
    if not changed:
        return flight

    # One record again, which is legal: TLS does not promise message
    # boundaries line up with record boundaries, and a client that assumes
    # they do is broken in a way worth catching here too.
    header = next(head for kind, head, _ in records if kind == 22)
    return (bytes([22]) + header[1:3] + len(rebuilt).to_bytes(2, "big")
            + bytes(rebuilt))


def truncate_the_ecdh_point(flight):
    """Drop one byte from the server's ephemeral point.

    The ServerKeyExchange for a named curve is `03 || group || len ||
    point`, so shortening the point means fixing three lengths - the
    point's, the handshake message's and the record's. Doing it by hand
    rather than with a byte search, for the reason in the function above.
    """
    records, offset = [], 0
    while offset < len(flight):
        length = int.from_bytes(flight[offset + 3:offset + 5], "big")
        records.append((flight[offset], flight[offset:offset + 3],
                        flight[offset + 5:offset + 5 + length]))
        offset += 5 + length

    stream = b"".join(body for kind, _, body in records if kind == 22)
    rebuilt, position = bytearray(), 0
    while position + 4 <= len(stream):
        message_type = stream[position]
        length = int.from_bytes(stream[position + 1:position + 4], "big")
        body = bytearray(stream[position + 4:position + 4 + length])
        if message_type == 12:                      # server_key_exchange
            point_length = body[3]
            del body[3 + point_length]              # the point's last byte
            body[3] = point_length - 1
            length -= 1
        rebuilt += bytes([message_type]) + length.to_bytes(3, "big") + body
        position += 4 + int.from_bytes(stream[position + 1:position + 4], "big")

    header = next(head for kind, head, _ in records if kind == 22)
    return (bytes([22]) + header[1:3] + len(rebuilt).to_bytes(2, "big")
            + bytes(rebuilt))


# ---------------------------------------------------------- TLS 1.3 resumption ---
#
# These are the only check there is on the PSK binder. The binder is an
# HMAC over a truncated ClientHello under a key derived through four
# steps, and every mistake in it produces a value that is perfectly
# self-consistent - a round trip against ourselves would pass whatever we
# got wrong. Only a server that computed the same binder independently
# can tell us, and OpenSSL is that server.


class Resumption:
    """One OpenSSL server context, two connections through it.

    The context is shared on purpose: the session ticket key lives in it,
    so a ticket from the first connection is only decryptable by the same
    context. A fresh one per connection would make every resumption fail
    for a reason that has nothing to do with us.
    """

    def __init__(self, **client_options):
        key, certificate = make_server_cert()
        self.cert_pem, cert_path, key_path = pem_files(key, certificate)
        self._paths = (cert_path, key_path)

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert_path, key_path)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3

        self.roots = allcrypt.TrustStore()
        self.roots.add_pem(self.cert_pem)
        self.client_options = dict(now=NOW, max_version="TLSv1.3",
                                   min_version="TLSv1.3")
        self.client_options.update(client_options)

    def cleanup(self):
        for path in self._paths:
            try:
                os.unlink(path)
            except OSError:
                pass

    def connect(self, tickets=()):
        """One handshake, then read enough to collect the tickets."""
        server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        server = self.context.wrap_bio(server_in, server_out, server_side=True)
        client = allcrypt.TlsClient("localhost", self.roots,
                                    tickets=list(tickets),
                                    **self.client_options)

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

        assert client.established, "the handshake did not finish"

        # Our Finished is still in the outgoing buffer: the client
        # considers itself established the moment it has sent it, and
        # the server is not finished until it has been delivered.
        for _ in range(5):
            data = client.take_outgoing()
            if data:
                server_in.write(data)
            try:
                server.do_handshake()
                break
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                data = server_out.read()
                if data:
                    client.push_incoming(data)
                    client.process()

        # The tickets come *after* the handshake, under the application
        # keys - so they arrive with or after the first data, and a
        # caller that looked immediately would find none. OpenSSL sends
        # them when it first writes.
        server.write(b"hello")
        client.push_incoming(server_out.read())
        client.process()
        assert client.take_incoming() == b"hello"

        return client, server, server_in, server_out


@pytest.fixture
def resumption():
    made = []

    def build(**options):
        pair = Resumption(**options)
        made.append(pair)
        return pair

    yield build
    for pair in made:
        pair.cleanup()


def test_a_session_resumes(resumption):
    """The whole thing end to end: a ticket from one connection makes the
    next one resume, which OpenSSL only agrees to if our binder is right."""
    session = resumption()

    first, server, _, _ = session.connect()
    assert not first.resumed
    tickets = first.take_tickets()
    assert tickets, "OpenSSL issued no session ticket"

    second, server, _, _ = session.connect(tickets=tickets[:1])
    assert second.resumed, "the server did not accept the pre-shared key"
    assert second.version() == "TLSv1.3"
    # A resumed connection carries no certificate: the PSK is what
    # authenticates the server.
    assert second.peer_certificates == []


def test_a_resumed_connection_still_carries_data(resumption):
    """A resumption that cannot carry data is not a connection. The
    application keys on a resumed handshake come from a schedule whose
    Early Secret has the PSK in it, so they differ from a fresh one's
    everywhere - and getting that wrong gives a handshake that finishes
    and a first record the server cannot decrypt."""
    session = resumption()
    first, *_ = session.connect()
    tickets = first.take_tickets()

    second, server, server_in, server_out = session.connect(
        tickets=tickets[:1])
    assert second.resumed

    second.write(b"over a resumed connection")
    server_in.write(second.take_outgoing())
    assert server.read(64) == b"over a resumed connection"

    server.write(b"and back again")
    second.push_incoming(server_out.read())
    second.process()
    assert second.take_incoming() == b"and back again"


def test_the_tickets_are_taken_not_copied(resumption):
    """A ticket is offered once. Reading without removing invites
    offering the same one twice, which is what its obfuscated age exists
    to prevent."""
    session = resumption()
    first, *_ = session.connect()
    assert first.take_tickets()
    assert first.take_tickets() == []


def test_a_ticket_for_another_host_is_not_offered(resumption):
    """RFC 8446 4.6.1 tells clients to store the name with the ticket and
    resume only against it. A ticket offered to the wrong host would be
    spent for nothing and would link the two connections."""
    session = resumption()
    first, *_ = session.connect()
    tickets = first.take_tickets()

    # Same server, different name asked for. The certificate covers
    # "localhost", so verification is off for this one - the point is
    # which tickets go out, not whether the name matches.
    other = Resumption(verify=False)
    other.context = session.context
    other.roots = session.roots
    try:
        client = allcrypt.TlsClient("elsewhere.test", other.roots,
                                    tickets=tickets, verify=False,
                                    now=NOW, max_version="TLSv1.3",
                                    min_version="TLSv1.3")
        server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        server = other.context.wrap_bio(server_in, server_out, server_side=True)
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
        assert client.established
        assert not client.resumed, \
            "a ticket issued for another host was offered and accepted"
    finally:
        other.cleanup()

    # The control: the same ticket against the name it was issued for
    # *does* resume, so the assertion above is about the hostname rather
    # than about resumption being broken.
    again, *_ = session.connect(tickets=tickets)
    assert again.resumed


def test_a_damaged_ticket_is_an_error_rather_than_a_silent_fresh_handshake(
        resumption):
    """A stored ticket that will not decode means the caller's storage is
    wrong. Quietly not resuming would look like a server that declined."""
    session = resumption()
    first, *_ = session.connect()
    ticket = bytearray(first.take_tickets()[0])
    ticket[0] ^= 0x01

    with pytest.raises(allcrypt.CryptoError):
        allcrypt.TlsClient("localhost", session.roots, tickets=[bytes(ticket)],
                           now=NOW, max_version="TLSv1.3")


def test_an_expired_ticket_is_dropped_rather_than_offered(resumption):
    """Dropped silently: a caller handing back a bag of stored tickets
    expects the unusable ones to be skipped, not to fail the
    connection."""
    session = resumption()
    first, *_ = session.connect()
    tickets = first.take_tickets()

    # A week and a day later, past the seven day cap.
    later = dict(session.client_options)
    later["now"] = NOW + 8 * 24 * 3600
    stale = Resumption()
    stale.context = session.context
    stale.roots = session.roots
    stale.client_options = later
    try:
        client, *_ = stale.connect(tickets=tickets[:1])
        assert not client.resumed
    finally:
        stale.cleanup()

    # The control: the same ticket at the original time resumes, so the
    # assertion above is about the clock.
    again, *_ = session.connect(tickets=tickets[:1])
    assert again.resumed


# ------------------------------------------- what check_live.py parses ---

def load_check_live():
    """`scripts/check_live.py` as a module.

    It is a hand-run development tool and stays one - it reaches the
    network and nothing in the gate may. What is imported here is three
    pure functions that read alert text, and nothing in this file calls
    anything that connects.
    """
    import importlib.util
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "..", "scripts", "check_live.py")
    spec = importlib.util.spec_from_file_location("check_live_probe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_check_live_reads_a_real_alert(handshake):
    """The alert text `check_live.py` classifies, taken from a handshake
    that really failed rather than typed into the test.

    **This test exists because of how its subject was got wrong.** The
    classifier has to tell "the peer declined" from "the peer read what we
    sent and could not parse it": the first says nothing about this
    library, the second is the bug that made three CryptoPro endpoints
    unreachable. It was written against `The peer sent a
    handshake_failure.` - a string nobody produces, because
    `tls::Alert::name` puts the level in front - and "verified" by calling
    the classifier with that same invented string, which of course agreed.

    So the input here comes from `exchange.client_error` after a real
    OpenSSL server has really refused us. A string this test cannot
    produce is a string the classifier must not be tuned to.
    """
    check_live = load_check_live()

    # An OpenSSL server pinned to TLS 1.0 while we offer 1.2, which is the
    # cheapest genuine refusal in this file.
    exchange = handshake(server_min=ssl.TLSVersion.TLSv1,
                         server_max=ssl.TLSVersion.TLSv1,
                         ciphers="AES128-SHA:@SECLEVEL=0").pump()
    assert not exchange.client.established
    text = str(exchange.client_error)
    assert "The peer sent a" in text, \
        f"this refusal did not come as an alert: {text!r}"

    alert = check_live.peer_alert(text)
    assert alert is not None, \
        f"check_live.py cannot read the alert text this library writes: {text!r}"
    assert check_live.peer_declined(text), \
        f"{alert} should read as the peer declining"
    assert not check_live.blames_us(text), \
        f"{alert} is not a bug of ours and must not be reported as one"


def test_check_live_blames_us_for_a_decode_error():
    """The other half, which is the half that matters.

    `decode_error` means the peer parsed our message and rejected it, and
    the classifier must **not** file it under "the server declined". The
    wording is pinned in `tls::mod`'s `test_alerts`, which asserts that
    `Alert::fatal(DECODE_ERROR).name()` is `fatal decode_error` - so this
    string is tied to the source by a test rather than by having been
    typed here.
    """
    check_live = load_check_live()
    text = "tls: The peer sent a fatal decode_error."

    assert check_live.peer_alert(text) == "decode_error"
    assert not check_live.peer_declined(text)
    assert check_live.blames_us(text), \
        "a decode_error is the server rejecting what we produced"

    # And the three outcomes that are not ours stay not ours.
    assert not check_live.blames_us("unreachable: [Errno 111] refused")
    assert not check_live.blames_us(
        "tls: The peer sent a fatal insufficient_security.")
    assert not check_live.blames_us(None)


def test_check_live_does_not_blame_us_for_the_servers_own_violation():
    """A refusal of *ours* about the peer's behaviour is not our bug.

    **The case that reaches a user.** `tlsgost-256.cryptopro.ru` answers a
    hello offering only suites it cannot serve with a ServerHello naming
    `0x0031` - a suite nobody offered, nobody here implements, and which
    is `TLS_DH_RSA_WITH_AES_128_CBC_SHA` to IANA - rather than sending
    `handshake_failure`. We refuse it and send the alert ourselves, so the
    error arrives with no "The peer sent a" anywhere in it and looks
    exactly like a failure of ours. The suite matrix filed it as a BUG row.

    **The phrases are checked against the source that writes them**, not
    typed here and hoped over. The classifier keys on a few fixed strings;
    this asserts each one still appears in `src/tls/client.rs`, so
    rewording that message fails this test rather than silently turning
    every such row back into a BUG. The wording itself is pinned against a
    real ServerHello by `tls::client::tests::test_the_message_names_what_was_offered`.

    The last time a string in this area was typed rather than taken from
    the code that produces it, the check it fed was wrong in both
    directions - see that Rust test's comment.
    """
    import os
    check_live = load_check_live()

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "src", "tls", "client.rs"),
              encoding="utf-8") as handle:
        source = handle.read()
    # Rust splits these literals across lines with a `\` continuation, so
    # the source text carries the phrase broken by whitespace. Collapsing
    # runs of whitespace is what makes a substring search meaningful.
    collapsed = " ".join(source.split())
    for phrase in check_live.PEER_BROKE_THE_RULE:
        assert phrase in collapsed, \
            f"check_live.py keys on {phrase!r} and client.rs no longer " \
            f"writes it; every such row would be reported as our bug"

    # And the classification itself, on a message built from those phrases.
    text = ("tls: illegal_parameter: The server chose unknown suite 0x0031, "
            "which this client did not offer - it offered 2 suite(s). "
            "RFC 5246 7.4.1.3 requires the selected suite to be one from "
            "the ClientHello, so this is the server breaking that, not a "
            "suite this library is missing.")
    assert check_live.peer_broke_the_rule(text)
    assert not check_live.blames_us(text), \
        "the server naming a suite nobody offered is not a defect here"
    assert not check_live.peer_declined(text), \
        "it is not a clean decline either - it is a protocol violation"


# --------------------------------------------------------------- X448 ---

@pytest.mark.parametrize("server_version,our_name", LEGACY_VERSIONS)
def test_x448_at_every_legacy_version(handshake, server_version, our_name):
    """X448 as a TLS 1.2 ECDHE group, against OpenSSL.

    RFC 8422 section 5.11 puts X25519 and X448 in the same place in the
    ServerKeyExchange - a raw u coordinate with a one-byte length, no
    format byte, no on-curve check - and our client handles both through
    one function. **That sharing is what this test is for.** The two
    curves differ in their clamp, their base point, their `a24` and
    whether there is a spare high bit, so a shared path that carried one
    curve's constant into the other produces a public key that is valid,
    a secret that is consistent, and a handshake that OpenSSL rejects at
    the Finished message.

    Which is also why this asserts data flowing both ways rather than
    stopping at `established`: a wrong shared secret is a wrong key
    schedule, and the first thing that notices is the peer's MAC.
    """
    exchange = handshake(ciphers="ECDHE-RSA-AES128-SHA:@SECLEVEL=0",
                         server_ecdh_curve="X448",
                         server_min=server_version, server_max=server_version,
                         min_version="TLSv1", max_version=our_name).pump()

    assert exchange.client_error is None, f"client failed: {exchange.client_error}"
    assert exchange.client.established
    assert exchange.client.named_group == "x448"
    assert exchange.send(b"curve448") == b"curve448"
    assert exchange.receive(b"and back") == b"and back"


def test_x448_at_tls13_costs_a_hello_retry_request():
    """X448 is offered but no key share is sent for it, on purpose.

    A share costs a key generation on every connection - 2.3 times an
    X25519 one here - and no server prefers X448, so it stays in
    `supported_groups` and a server that wants it asks. That ask is a
    HelloRetryRequest, and this is the test that the retry path works for
    a group whose share we did not pre-generate.

    Asserted on `named_group` rather than on the retry itself: what the
    caller cares about is that a server insisting on X448 gets a working
    connection, and a client that quietly fell back to X25519 instead
    would pass a test that only checked `established`.
    """
    exchange = Handshake(server_ecdh_curve="X448", ciphers=None,
                         min_version="TLSv1.3", max_version="TLSv1.3",
                         server_min=ssl.TLSVersion.TLSv1_3,
                         server_max=ssl.TLSVersion.TLSv1_3)
    try:
        exchange.pump()
        assert exchange.client_error is None, \
            f"client failed: {exchange.client_error}"
        assert exchange.client.established
        assert exchange.client.version() == "TLSv1.3"
        assert exchange.client.named_group == "x448"
        assert exchange.send(b"retried") == b"retried"
        assert exchange.receive(b"and back") == b"and back"
    finally:
        exchange.cleanup()


def test_an_x448_key_of_the_wrong_length_is_refused(handshake):
    """The one thing that can be wrong about an X448 public key is its
    width, and **32 is the dangerous wrong width**: an X25519 key is a
    perfectly good 32 byte string, and a client that padded it to 56
    would compute a secret from a value the server never chose.

    `truncate_the_ecdh_point` cuts the point short, which is the same
    failure in a form this harness can produce.
    """
    exchange = handshake(ciphers="ECDHE-RSA-AES128-SHA:@SECLEVEL=0",
                         server_ecdh_curve="X448")

    exchange.server_in.write(exchange.client.take_outgoing())
    try:
        exchange.server.do_handshake()
    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
        pass
    flight = exchange.server_out.read()
    assert flight

    exchange.client.push_incoming(truncate_the_ecdh_point(flight))
    with pytest.raises(allcrypt.CryptoError) as info:
        exchange.client.process()
    assert not exchange.client.established
    # The width check or the signature check, either of which is a real
    # refusal. The width must be named as 56 and never as 32.
    text = str(info.value)
    assert "56 bytes" in text or "signature" in text.lower(), text
    assert "32 bytes" not in text, \
        f"an X448 key was measured against X25519's width: {text}"
