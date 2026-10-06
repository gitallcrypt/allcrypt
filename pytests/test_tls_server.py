"""Complete TLS handshakes, against OpenSSL as the **client**.

The mirror of ``test_tls_handshake.py``: there our client talks to an
OpenSSL server, here an OpenSSL client talks to our server. Everything on
our side of the wire is this library's own code, down to the bignum
arithmetic.

This is the only check that matters for `tls/server.rs`. Our client
against our server settles the wiring and nothing else - both ends are
ours, so a byte order wrong in the same way twice agrees with itself
perfectly. The ServerKeyExchange signature is the example: it covers
``client_random || server_random || ServerECDHParams``, and a server that
signs only the params produces something our own client would accept if
it made the same mistake. Only OpenSSL can say.

Both sides run over memory BIOs and are pumped by hand, so there is no
socket, no timing and no flakiness. A failure here is a protocol bug.

The certificate and its key come from `cryptography`, not from our own
builder, for the same reason: our server has to present a certificate
somebody else made and sign with a key somebody else generated.
"""

import datetime
import ssl
import time

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


def make_cert(key, common_name="localhost", sans=("localhost",)):
    """A self-signed certificate for `key`, which is both leaf and root."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(1)
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=3650))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                              critical=True)
               .add_extension(usage(digital_signature=True,
                                    key_encipherment=True,
                                    key_cert_sign=True, crl_sign=True),
                              critical=True)
               .add_extension(
                   x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                   critical=False))
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]),
            critical=False)
    return builder.sign(key, hashes.SHA256())


def ec_identity(curve=ec.SECP256R1(), curve_name="P-256"):
    """An EC key from `cryptography`, and the same key as ours.

    The private scalar crosses over as bytes, so our server signs with
    the key OpenSSL will check against the certificate. A key generated
    on our side and a certificate built on theirs would be two keys.
    """
    key = ec.generate_private_key(curve)
    certificate = make_cert(key)
    scalar = key.private_numbers().private_value
    size = (key.curve.key_size + 7) // 8
    ours = allcrypt.EcKey.from_private(curve_name,
                                       scalar.to_bytes(size, "big"))
    return ours, certificate


def rsa_identity(bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    certificate = make_cert(key)
    numbers = key.private_numbers()
    byte_length = lambda n: (n.bit_length() + 7) // 8
    ours = allcrypt.RsaKey.from_primes(
        numbers.p.to_bytes(byte_length(numbers.p), "big"),
        numbers.q.to_bytes(byte_length(numbers.q), "big"),
        (65537).to_bytes(3, "big"))
    return ours, certificate


class Handshake:
    """An OpenSSL client and our server, pumped by hand over memory BIOs."""

    def __init__(self, *, identity=None, hostname="localhost",
                 client_ciphers=None,
                 client_min=ssl.TLSVersion.TLSv1_2,
                 client_max=ssl.TLSVersion.TLSv1_2,
                 client_groups=None,
                 verify=True, _chain=None, _roots_pem=None, **server_options):
        key, certificate = identity if identity else ec_identity()
        if _chain is not None:
            # A chain built by this library rather than by
            # `cryptography`, with a separate trust anchor: the
            # certificate the client verifies against is *not* the one
            # the server presents, which is what makes the signature
            # check mean something.
            chain = list(_chain)
            self.cert_pem = _roots_pem
        else:
            chain = [certificate.public_bytes(serialization.Encoding.DER)]
            self.cert_pem = certificate.public_bytes(
                serialization.Encoding.PEM).decode()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if client_ciphers:
            context.set_ciphers(client_ciphers)
        context.minimum_version = client_min
        context.maximum_version = client_max
        if client_groups:
            # Pins the *client* to one group, so a test can assert which
            # group our server chose rather than whichever OpenSSL happens
            # to prefer this release. `set_ecdh_curve` is
            # SSL_CTX_set1_groups under the name it had when only ECDH
            # used it, and it applies to a client context too.
            context.set_ecdh_curve(client_groups)
        if verify:
            context.load_verify_locations(cadata=self.cert_pem)
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        self.client_in, self.client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.client = context.wrap_bio(self.client_in, self.client_out,
                                       server_hostname=hostname)

        self.server = allcrypt.TlsServer(chain, key, **server_options)
        self.client_error = None
        self.server_error = None

    def pump(self, rounds=20):
        """Run the handshake to completion, or until something fails."""
        for _ in range(rounds):
            try:
                self.client.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            except ssl.SSLError as reason:
                self.client_error = reason

            data = self.client_out.read()
            if data:
                self.server.push_incoming(data)

            try:
                self.server.process()
            except ValueError as reason:
                self.server_error = reason

            out = self.server.take_outgoing()
            if out:
                self.client_in.write(out)

            if self.server_error or self.client_error:
                # An alert the server sent is in the client's BIO but
                # nothing has read it yet, and a client that never sees
                # it looks exactly like one that timed out. So give it
                # one more turn before stopping.
                try:
                    self.client.do_handshake()
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
                except ssl.SSLError as reason:
                    self.client_error = reason
                break
            if self.server.established and not out and not data:
                break
        return self

    def send_from_client(self, payload):
        self.client.write(payload)
        self.server.push_incoming(self.client_out.read())
        self.server.process()
        return self.server.take_incoming()

    def send_from_server(self, payload):
        self.server.write(payload)
        self.client_in.write(self.server.take_outgoing())
        return self.client.read(len(payload))


# ---------------------------------------------------------- the happy path ---

def test_openssl_completes_an_ecdhe_ecdsa_handshake():
    """The one that settles the ServerKeyExchange signature.

    OpenSSL verifies the signature over
    ``client_random || server_random || ServerECDHParams`` before it
    sends its own key exchange. Nothing on our side can check that: our
    client would accept whatever our server produced.
    """
    handshake = Handshake().pump()
    assert handshake.client_error is None, handshake.client_error
    assert handshake.server_error is None, handshake.server_error
    assert handshake.server.established
    assert handshake.server.version() == "TLSv1.2"
    assert handshake.client.version() == "TLSv1.2"


def test_openssl_completes_an_ecdhe_rsa_handshake():
    handshake = Handshake(identity=rsa_identity()).pump()
    assert handshake.server_error is None, handshake.server_error
    assert handshake.server.established
    name, _, _ = handshake.server.cipher()
    assert "ECDHE_RSA" in name, name


def test_data_crosses_in_both_directions():
    """Each side derives its keys independently; this is where that shows."""
    handshake = Handshake().pump()
    assert handshake.server.established

    assert handshake.send_from_client(b"hello from openssl") == \
        b"hello from openssl"
    assert handshake.send_from_server(b"hello from us") == b"hello from us"


def test_a_record_larger_than_one_record_is_reassembled():
    """16 KB is the record limit, so this is several records in each
    direction and exercises the sequence number rather than just the
    first record's."""
    handshake = Handshake().pump()
    assert handshake.server.established

    payload = bytes((i * 7 + 3) & 0xff for i in range(50_000))
    handshake.client.write(payload)
    received = b""
    while len(received) < len(payload):
        data = handshake.client_out.read()
        if not data:
            break
        handshake.server.push_incoming(data)
        handshake.server.process()
        received += handshake.server.take_incoming()
    assert received == payload


def test_the_server_reports_the_name_the_client_asked_for():
    """SNI, which is the whole reason a proxy terminates TLS."""
    handshake = Handshake().pump()
    assert handshake.server.server_name == "localhost"


def test_a_client_that_sends_no_sni_gives_none():
    """An IP-address connection has no SNI, and that is not a failure -
    it is a proxy with only an address to go on."""
    # `server_hostname` must be set for verification, so this one does
    # not verify: the point is the absence of the extension.
    handshake = Handshake(hostname=None, verify=False).pump()
    assert handshake.server.established
    assert handshake.server.server_name is None


# ------------------------------------------------------ what was negotiated ---

@pytest.mark.parametrize("openssl_name", [
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
])
def test_each_ecdsa_suite_completes(openssl_name):
    """One handshake per suite, driven from the client's side.

    A suite that only ever appears in a list is not tested by being in
    the list: the server picks one and the rest are never built.
    """
    handshake = Handshake(client_ciphers=openssl_name).pump()
    assert handshake.server_error is None, handshake.server_error
    assert handshake.server.established
    assert handshake.client.cipher()[0] == openssl_name


@pytest.mark.parametrize("openssl_name", [
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
])
def test_each_rsa_suite_completes(openssl_name):
    """The last two are RSA key transport, which is the Bleichenbacher
    path: the premaster is decrypted rather than agreed."""
    handshake = Handshake(identity=rsa_identity(),
                          client_ciphers=openssl_name).pump()
    assert handshake.server_error is None, handshake.server_error
    assert handshake.server.established
    assert handshake.client.cipher()[0] == openssl_name


@pytest.mark.parametrize("openssl_name", [
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-ECDSA-AES256-SHA",
])
def test_the_cbc_suites_complete(openssl_name):
    """CBC is a different record layer: a MAC, padding, and an explicit
    IV. It is also the half that encrypt-then-MAC applies to."""
    handshake = Handshake(client_ciphers=openssl_name + ":@SECLEVEL=0").pump()
    assert handshake.server_error is None, handshake.server_error
    assert handshake.server.established
    assert handshake.send_from_client(b"over CBC") == b"over CBC"


def test_encrypt_then_mac_is_agreed_and_used():
    handshake = Handshake(client_ciphers="ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0")
    handshake.pump()
    assert handshake.server.established
    assert handshake.server.encrypt_then_mac
    assert handshake.send_from_client(b"etm") == b"etm"


def test_mac_then_encrypt_works_when_the_server_declines():
    """The MAC-then-encrypt path, which is the one Lucky 13 applies to.

    Reached by having *our* server decline RFC 7366, not by having
    OpenSSL stop offering it: `OP_NO_ENCRYPT_THEN_MAC` does not exist on
    this Python, so `getattr(ssl, ..., 0)` sets nothing and a test
    written that way negotiates encrypt-then-MAC while claiming to test
    the other path. The client-side mirror of this made exactly that
    mistake - see the note on `test_without_encrypt_then_mac` in
    `test_tls_handshake.py`.

    Declining is a real capability rather than a test hook: some old
    equipment mishandles the extension, and reaching one of those means
    being able to stop agreeing to it.
    """
    handshake = Handshake(client_ciphers="ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0",
                          allow_encrypt_then_mac=False)
    handshake.pump()
    assert handshake.server.established, handshake.server_error
    assert not handshake.server.encrypt_then_mac, (
        "encrypt-then-MAC was agreed even though the server declined it")
    assert handshake.send_from_client(b"mac then encrypt") == b"mac then encrypt"
    assert handshake.send_from_server(b"and back again") == b"and back again"

    # Several records, because the padding and the MAC are per record and
    # the first one is the easiest to get right by accident.
    for index in range(8):
        message = bytes([index]) * (index * 7 + 1)
        assert handshake.send_from_client(message) == message


def test_the_extended_master_secret_is_agreed():
    """RFC 7627. OpenSSL sends the extension by default, so a server
    that ignored it would complete the handshake with a different
    master secret and fail at the Finished."""
    handshake = Handshake().pump()
    assert handshake.server.established
    assert handshake.server.extended_master_secret


def test_without_the_extended_master_secret_the_handshake_still_works():
    """The original derivation, which everything before 2015 uses."""
    handshake = Handshake(allow_extended_master_secret=False).pump()
    assert handshake.server_error is None, handshake.server_error
    assert handshake.server.established
    assert not handshake.server.extended_master_secret
    assert handshake.send_from_client(b"no ems") == b"no ems"


def test_the_server_order_decides():
    """The server's list is in the server's order, and the first suite
    the client also offered wins - whatever the client put first."""
    handshake = Handshake(
        client_ciphers="ECDHE-ECDSA-AES256-GCM-SHA384:"
                       "ECDHE-ECDSA-AES128-GCM-SHA256",
        ciphers="ECDHE-ECDSA-AES128-GCM-SHA256,"
                "ECDHE-ECDSA-AES256-GCM-SHA384").pump()
    assert handshake.server.established
    assert handshake.client.cipher()[0] == "ECDHE-ECDSA-AES128-GCM-SHA256"


def test_the_curve_the_client_offered_is_the_one_used():
    """The group comes from the client's supported_groups, not from a
    fixed choice: a server that always picked P-256 would work against
    every client that offers it and fail against one that does not."""
    handshake = Handshake(identity=ec_identity(ec.SECP384R1(), "P-384"),
                          client_ciphers="ECDHE-ECDSA-AES256-GCM-SHA384")
    handshake.pump()
    assert handshake.server_error is None, handshake.server_error
    assert handshake.server.established


@pytest.mark.parametrize("client_max,expected_version", [
    (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
    (ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
])
def test_a_p521_server_to_an_openssl_client(client_max, expected_version):
    """Our server with a P-521 key, to an OpenSSL client pinned to P-521.

    The mirror of the client-side P-521 tests: OpenSSL checks our 133
    byte points, both ECDSA signatures (the 1.2 ServerKeyExchange and the
    1.3 CertificateVerify) and the shared secret's 66 byte width."""
    handshake = Handshake(identity=ec_identity(ec.SECP521R1(), "P-521"),
                          client_groups="secp521r1",
                          client_min=ssl.TLSVersion.TLSv1_2,
                          client_max=client_max,
                          client_ciphers="ECDHE-ECDSA-AES256-GCM-SHA384"
                          if client_max == ssl.TLSVersion.TLSv1_2 else None)
    handshake.pump()
    assert handshake.server_error is None, handshake.server_error
    assert handshake.server.established
    assert handshake.client.version() == expected_version
    assert handshake.send_from_client(b"P-521") == b"P-521"
    assert handshake.send_from_server(b"and back") == b"and back"


@pytest.mark.parametrize("group", ["X25519", "X448"])
@pytest.mark.parametrize("client_max,expected_version", [
    (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
    (ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
])
def test_a_montgomery_group_from_an_openssl_client(group, client_max,
                                                   expected_version):
    """An OpenSSL client pinned to one Montgomery group, at both versions.

    **The mirror that matters for X448.** Our client against an OpenSSL
    server proves we can consume their public key; this proves they can
    consume ours, which is a different claim and fails differently. A
    public key built from the wrong base point, or with the clamp applied
    where it should not be, still yields a self-consistent exchange - our
    own client would agree with it. OpenSSL is what does not.

    X25519 is parametrised alongside it deliberately: the two share one
    code path in `tls::kex` and a constant carried from one to the other
    is the failure that path invites, so both must pass at once for either
    result to mean anything.

    Both versions, because the group is used in two entirely different
    messages - a ServerKeyExchange at 1.2, a key_share at 1.3 - and only
    the second is length-prefixed by the extension itself.

    **An RSA certificate, not the EC one the neighbouring tests use**, and
    that is not a style choice. At TLS 1.2, RFC 4492 gives
    `supported_groups` a second job: it constrains the curve of an *ECDSA
    certificate* as well as the ECDHE group. Pinning this client to
    X25519 therefore makes our P-256 certificate unacceptable, and OpenSSL
    says so with `illegal_parameter` - which reads exactly like a
    malformed ServerKeyExchange and sent me looking at the wrong file.
    TLS 1.3 does not do this: there the certificate's curve comes from
    `signature_algorithms`, which is why the 1.3 rows passed with the EC
    identity while both 1.2 rows failed.
    """
    handshake = Handshake(identity=rsa_identity(), client_groups=group,
                          client_min=ssl.TLSVersion.TLSv1_2,
                          client_max=client_max,
                          client_ciphers="ECDHE-RSA-AES128-GCM-SHA256"
                          if client_max == ssl.TLSVersion.TLSv1_2 else None)
    handshake.pump()
    assert handshake.server_error is None, handshake.server_error
    assert handshake.server.established
    assert handshake.client.version() == expected_version
    # And the secret is right, which `established` does not say: a wrong
    # shared secret is a wrong key schedule, and application data is the
    # first thing that notices in each direction.
    assert handshake.send_from_client(b"montgomery") == b"montgomery"
    assert handshake.send_from_server(b"and back") == b"and back"


# ------------------------------------------------------ what must not happen ---

def test_a_client_with_no_suite_in_common_is_refused():
    """And refused with an alert, so the client is not left waiting."""
    handshake = Handshake(client_ciphers="ECDHE-RSA-AES128-GCM-SHA256")
    handshake.pump()
    assert not handshake.server.established
    assert handshake.server_error is not None
    # The client heard about it rather than timing out.
    assert handshake.client_error is not None


def test_an_ec_server_never_chooses_an_rsa_suite():
    """It has no key for one. A client offering both must get the EC
    one, not a handshake that fails at the signature."""
    handshake = Handshake(
        client_ciphers="ECDHE-RSA-AES128-GCM-SHA256:"
                       "ECDHE-ECDSA-AES128-GCM-SHA256",
        ciphers="all").pump()
    assert handshake.server.established
    assert handshake.client.cipher()[0] == "ECDHE-ECDSA-AES128-GCM-SHA256"


def test_a_tls_1_3_only_client_is_refused_by_a_1_2_server():
    """A server whose ceiling is 1.2 says so rather than negotiating
    something it cannot finish.

    This used to assert that *no* server here speaks 1.3, which stopped
    being true when `server13.rs` landed. The property worth keeping is
    the one about the ceiling: `max_version` is a limit the server
    actually applies, not a description of what it happens to implement.
    The 1.3 handshakes themselves are in `test_tls13_server.py`.
    """
    handshake = Handshake(client_min=ssl.TLSVersion.TLSv1_3,
                          client_max=ssl.TLSVersion.TLSv1_3,
                          max_version="TLSv1.2")
    handshake.pump()
    assert not handshake.server.established


def test_a_client_below_the_floor_is_refused():
    """A 1.2 server offered TLS 1.0 refuses it, rather than coming
    down."""
    handshake = Handshake(client_min=ssl.TLSVersion.TLSv1,
                          client_max=ssl.TLSVersion.TLSv1,
                          client_ciphers="ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0")
    handshake.pump()
    assert not handshake.server.established


def test_tampering_with_a_record_is_caught():
    """One flipped bit in an application data record, which the MAC or
    the AEAD tag has to reject."""
    handshake = Handshake().pump()
    assert handshake.server.established

    handshake.client.write(b"the payload")
    record = bytearray(handshake.client_out.read())
    record[-1] ^= 0x01
    handshake.server.push_incoming(bytes(record))
    with pytest.raises(ValueError):
        handshake.server.process()


def test_a_truncated_flight_leaves_the_server_waiting_not_established():
    """Half a ClientHello is not a ClientHello."""
    handshake = Handshake()
    handshake.client.do_handshake_on_connect = False
    try:
        handshake.client.do_handshake()
    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
        pass
    hello = handshake.client_out.read()
    handshake.server.push_incoming(hello[:len(hello) // 2])
    handshake.server.process()
    assert not handshake.server.established
    assert handshake.server.handshaking


def test_garbage_is_an_error_not_a_crash():
    key, certificate = ec_identity()
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    for seed in range(50):
        server = allcrypt.TlsServer([cert_der], key)
        server.push_incoming(bytes((i * 37 + seed * 11) & 0xff
                                   for i in range(200)))
        try:
            server.process()
        except ValueError:
            pass
        assert not server.established


# ------------------------------------------------------------ configuration ---

def test_a_server_without_a_certificate_is_refused():
    key, _ = ec_identity()
    with pytest.raises(ValueError):
        allcrypt.TlsServer([], key)


def test_a_key_that_is_not_a_key_is_refused():
    _, certificate = ec_identity()
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    with pytest.raises(ValueError):
        allcrypt.TlsServer([cert_der], b"not a key")


# ------------------------------------- the certificate authority, end to end ---

def ca_identity(ca, host="localhost"):
    """A leaf issued by our own CA, as a `Handshake` identity.

    Note what this replaces: everywhere above, `cryptography` built the
    certificate and our server merely presented it. Here the whole chain
    is ours - our CA, our issuance, our signature - and OpenSSL is asked
    to *verify* it rather than just to complete a handshake with it.
    """
    not_before = time.strftime("%Y%m%d%H%M%SZ",
                               time.gmtime(time.time() - 86400))
    not_after = time.strftime("%Y%m%d%H%M%SZ",
                              time.gmtime(time.time() + 86400))
    leaf_der, leaf_key = ca.issue(host, not_before, not_after)
    return allcrypt.EcKey.from_private("P-256", leaf_key), leaf_der


def make_ca(name="allcrypt proxy CA"):
    not_before = time.strftime("%Y%m%d%H%M%SZ",
                               time.gmtime(time.time() - 86400))
    not_after = time.strftime("%Y%m%d%H%M%SZ",
                              time.gmtime(time.time() + 365 * 86400))
    return allcrypt.CertificateAuthority(name, not_before, not_after)


class CaHandshake(Handshake):
    """The same harness, with our CA as the client's trust anchor.

    The base class trusts the leaf directly, which proves the handshake
    works but says nothing about the chain: a self-signed leaf trusted
    as a root verifies without anybody checking a signature made by
    somebody else.
    """

    def __init__(self, ca, host="localhost", **kwargs):
        key, leaf_der = ca_identity(ca, host)
        self._ca = ca
        super().__init__(identity=(key, None), hostname=host,
                         _chain=[leaf_der], _roots_pem=ca.certificate_pem,
                         **kwargs)


def test_openssl_verifies_a_chain_our_ca_issued():
    """**The proxy's browser-facing side, end to end.**

    OpenSSL builds the path from our leaf to our CA, checks our ECDSA
    signature over our own DER, checks the name against our
    subjectAltName, and only then completes the handshake. Nothing in
    this library is on the judging side of any of it.

    Which also makes it the first check that the certificates our
    builder writes are ones a real verifier will *chain*, as opposed to
    ones it will parse. Those are different: the validity-date bug
    (RFC 5280 4.1.2.5) produced certificates that parsed perfectly here
    and were refused outright by everybody else.
    """
    ca = make_ca()
    handshake = CaHandshake(ca).pump()
    assert handshake.client_error is None, handshake.client_error
    assert handshake.server_error is None, handshake.server_error
    assert handshake.server.established
    assert handshake.send_from_client(b"through the proxy") == \
        b"through the proxy"


def test_a_leaf_from_a_different_ca_is_refused():
    """And the verification above is real, not verification switched off.

    Same shape, same names, same extensions - a different signature.
    """
    ca = make_ca()
    other = make_ca("someone else's CA")
    key, leaf_der = ca_identity(other)
    handshake = Handshake(identity=(key, None), _chain=[leaf_der],
                          _roots_pem=ca.certificate_pem)
    handshake.pump()
    assert not handshake.server.established or handshake.client_error
    assert handshake.client_error is not None, \
        "OpenSSL accepted a leaf signed by a CA it does not trust"


def test_a_certificate_for_another_name_is_refused():
    """The name is checked too, so the success above is about this leaf."""
    ca = make_ca()
    key, leaf_der = ca_identity(ca, host="somewhere-else.test")
    handshake = Handshake(identity=(key, None), _chain=[leaf_der],
                          _roots_pem=ca.certificate_pem)
    handshake.pump()
    assert handshake.client_error is not None, \
        "OpenSSL accepted a certificate for a different name"


def test_a_certificate_is_issued_per_host():
    """What a proxy does on every CONNECT: read the host, issue for it.

    Three hosts, three certificates, each verified by OpenSSL against
    the one CA - which is the thing a browser would have installed.
    """
    ca = make_ca()
    for host in ["localhost", "one.test", "two.test"]:
        handshake = CaHandshake(ca, host=host).pump()
        assert handshake.client_error is None, f"{host}: {handshake.client_error}"
        assert handshake.server.established, host
        assert handshake.server.server_name == host


def test_the_ca_key_and_certificate_round_trip():
    """A proxy stores these between runs; a mismatched pair is refused."""
    ca = make_ca()
    again = allcrypt.CertificateAuthority.from_parts(ca.private_bytes,
                                                     ca.certificate)
    assert again.common_name == ca.common_name
    assert again.key_identifier == ca.key_identifier

    # A leaf from the rebuilt CA still chains to the original
    # certificate, which is the only thing that matters.
    handshake = CaHandshake(again).pump()
    assert handshake.client_error is None, handshake.client_error
    assert handshake.server.established

    other = make_ca("other")
    with pytest.raises(ValueError):
        allcrypt.CertificateAuthority.from_parts(other.private_bytes,
                                                 ca.certificate)


def test_what_the_ca_actually_writes_into_its_certificates():
    """The extensions, read back by `cryptography` rather than by us.

    OpenSSL's path verifier does not catch a mistake in any of these:
    a certificate loaded as a trust anchor is trusted by fiat, so a CA
    with no `basicConstraints` still verifies its own leaves here. A
    browser is stricter, and RFC 5280 requires several of these
    outright - so they are asserted directly, by somebody else's parser.

    Found by deliberately breaking the issuance: removing
    `basicConstraints` from the CA and removing the key identifiers from
    the leaf both left all thirty-six handshake tests passing.
    """
    ca = make_ca()
    ca_cert = x509.load_der_x509_certificate(ca.certificate)
    _, leaf_der = ca_identity(ca, host="a-host.test")
    leaf = x509.load_der_x509_certificate(leaf_der)

    # --- the CA ---
    basic = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic.critical, "basicConstraints must be critical on a CA"
    assert basic.value.ca is True
    assert basic.value.path_length == 0, (
        "this CA signs leaves and nothing else; one that can make an "
        "intermediate is one whose key can delegate")

    usage = ca_cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert usage.value.key_cert_sign
    assert not usage.value.digital_signature, (
        "a CA that can also sign data is a CA whose key does two jobs")

    ca_ski = ca_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier).value
    # RFC 5280 4.2.1.2: "this extension MUST appear in all conforming CA
    # certificates". A verifier that looks certificates up by it finds
    # nothing without one.
    assert ca_ski.digest == ca.key_identifier
    assert ca_cert.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier).value.key_identifier == ca_ski.digest, \
        "a self-signed root names itself"

    # --- the leaf ---
    with pytest.raises(x509.ExtensionNotFound):
        leaf.extensions.get_extension_for_class(x509.BasicConstraints)

    usage = leaf.extensions.get_extension_for_class(x509.KeyUsage)
    assert usage.value.digital_signature
    assert not usage.value.key_cert_sign, "the leaf can issue certificates"

    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value

    leaf_aki = leaf.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier).value
    assert leaf_aki.key_identifier == ca_ski.digest, \
        "the leaf names an issuer key that is not this CA's"
    leaf_ski = leaf.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier).value
    assert leaf_ski.digest != ca_ski.digest, \
        "the leaf's own identifier is the CA's, so one field holds the " \
        "wrong key"
    assert leaf_ski.digest == x509.SubjectKeyIdentifier.from_public_key(
        leaf.public_key()).digest

    assert leaf.subject.rfc4514_string() == "CN=a-host.test"
    assert leaf.issuer == ca_cert.subject


def test_a_host_and_an_address_take_different_san_forms():
    """A verifier asked about an address looks only at iPAddress
    entries, so an address written as a dNSName matches nothing - and
    says nothing about why."""
    import ipaddress
    ca = make_ca()

    _, der = ca_identity(ca, host="a-host.test")
    sans = x509.load_der_x509_certificate(der).extensions \
        .get_extension_for_class(x509.SubjectAlternativeName).value
    assert sans.get_values_for_type(x509.DNSName) == ["a-host.test"]
    assert sans.get_values_for_type(x509.IPAddress) == []

    for host, expected in [("192.0.2.1", ipaddress.ip_address("192.0.2.1")),
                           ("2001:db8::1", ipaddress.ip_address("2001:db8::1"))]:
        _, der = ca_identity(ca, host=host)
        sans = x509.load_der_x509_certificate(der).extensions \
            .get_extension_for_class(x509.SubjectAlternativeName).value
        assert sans.get_values_for_type(x509.IPAddress) == [expected], host
        assert sans.get_values_for_type(x509.DNSName) == [], host
