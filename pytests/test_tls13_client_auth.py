"""TLS 1.3 client certificates, both directions, against OpenSSL.

Client authentication is the one place where the two ends of this library
are doing *different* work from the same specification, so each half needs
somebody else on the wire:

* Our server asks, and a real `ssl.SSLContext` client answers. That
  settles our CertificateRequest (OpenSSL parses it and picks a scheme
  from it) and our verification of a signature somebody else made.
* Our client answers, and a real OpenSSL server asks. That settles the
  message we *send* - the transcript it covers, the context string, the
  scheme - which our own server would accept however wrong it was, since
  it makes the same choices.

The context string is the sharpest example. `Side13::Client` and
`Side13::Server` differ by one word, and signing with the wrong one
produces a signature that verifies against nothing and looks exactly like
a key that does not match its certificate. Our two ends agreeing on the
wrong word is a handshake that works perfectly between them and with
nobody.

**No network.** Both halves run over memory BIOs; `conftest.py` refuses
anything else.
"""

import datetime
import ssl
import time

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import allcrypt

from test_tls_server import ec_identity, usage

NOW = int(time.time())
TLS13 = ssl.TLSVersion.TLSv1_3

PEM = serialization.Encoding.PEM
DER = serialization.Encoding.DER


# ------------------------------------------------------------ the identity ---

def _client_ca():
    """A CA that exists only to issue client identities.

    Separate from the server's certificate on purpose: `client_roots` is
    a different set from the roots a client uses to judge a server, and a
    test where the two are the same cannot tell whether the server
    consulted the right one.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(7)
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=3650))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                  critical=True)
                   .add_extension(usage(digital_signature=True,
                                        key_cert_sign=True, crl_sign=True),
                                  critical=True)
                   .sign(key, hashes.SHA256()))
    return key, certificate


def _issue(ca_key, ca_certificate, subject_key, common_name="a client",
           eku=(ExtendedKeyUsageOID.CLIENT_AUTH,)):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name(
                   [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
               .issuer_name(ca_certificate.subject)
               .public_key(subject_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=365))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                              critical=True)
               .add_extension(usage(digital_signature=True), critical=True)
               .add_extension(
                   x509.AuthorityKeyIdentifier.from_issuer_public_key(
                       ca_key.public_key()), critical=False))
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(list(eku)),
                                        critical=False)
    return builder.sign(ca_key, hashes.SHA256())


class ClientIdentity:
    """A client's certificate and key, in every shape a test needs.

    `paths` writes the PEM out because `load_cert_chain` takes files and
    nothing else; `ours` is the same key as an `allcrypt` object, so our
    client signs with the key the server will check.
    """

    def __init__(self, tmp_path, kind="ec", eku=(ExtendedKeyUsageOID.CLIENT_AUTH,),
                 ca=None):
        self.ca_key, self.ca_certificate = ca if ca else _client_ca()
        if kind == "ec":
            key = ec.generate_private_key(ec.SECP256R1())
            scalar = key.private_numbers().private_value
            self.ours = allcrypt.EcKey.from_private("P-256",
                                                    scalar.to_bytes(32, "big"))
        elif kind in ("ed25519", "ed448"):
            module = ed25519.Ed25519PrivateKey if kind == "ed25519" \
                else ed448.Ed448PrivateKey
            key = module.generate()
            seed = key.private_bytes(serialization.Encoding.Raw,
                                     serialization.PrivateFormat.Raw,
                                     serialization.NoEncryption())
            self.ours = allcrypt.EddsaKey.from_private(kind, seed)
        else:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            numbers = key.private_numbers()
            length = lambda n: (n.bit_length() + 7) // 8
            self.ours = allcrypt.RsaKey.from_primes(
                numbers.p.to_bytes(length(numbers.p), "big"),
                numbers.q.to_bytes(length(numbers.q), "big"),
                (65537).to_bytes(3, "big"))
        self.key = key
        self.certificate = _issue(self.ca_key, self.ca_certificate, key, eku=eku)
        self.chain = [self.certificate.public_bytes(DER)]
        self.ca_pem = self.ca_certificate.public_bytes(PEM).decode()

        # The serial, because two identities in one test share a
        # `tmp_path` and a fixed name would have the second silently
        # overwrite the first - which reads as the server accepting a
        # chain it should have refused.
        stem = f"client-{kind}-{self.certificate.serial_number:x}"
        self.path = tmp_path / f"{stem}.pem"
        self.path.write_bytes(
            self.certificate.public_bytes(PEM)
            + key.private_bytes(PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))
        self.ca_path = tmp_path / f"{stem}-ca.pem"
        self.ca_path.write_text(self.ca_pem)

    def roots(self):
        store = allcrypt.TrustStore()
        store.add_pem(self.ca_pem)
        return store


# -------------------------------------------- our server, OpenSSL's client ---

class OurServer:
    """An OpenSSL client and our server over memory BIOs."""

    def __init__(self, *, identity=None, client_identity=None,
                 version=TLS13, **options):
        self.key, certificate = identity if identity else ec_identity()
        chain = [certificate.public_bytes(DER)]

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = version
        context.maximum_version = version
        context.load_verify_locations(
            cadata=certificate.public_bytes(PEM).decode())
        if client_identity is not None:
            context.load_cert_chain(str(client_identity.path))

        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.client = context.wrap_bio(self.incoming, self.outgoing,
                                       server_hostname="localhost")
        name = {ssl.TLSVersion.TLSv1_2: "TLSv1.2", TLS13: "TLSv1.3"}[version]
        options.setdefault("now", NOW)
        options.setdefault("max_version", name)
        options.setdefault("min_version", name)
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


def test_an_openssl_client_authenticates(tmp_path):
    """The one that matters for our server.

    OpenSSL parsed our CertificateRequest, chose a scheme from the list
    inside it, signed the transcript it built itself with the *client's*
    context string, and we agreed. None of those four is checkable
    against ourselves.
    """
    client = ClientIdentity(tmp_path)
    run = OurServer(client_identity=client,
                    request_client_certificate=True,
                    require_client_certificate=True,
                    client_roots=client.roots()).pump()

    assert run.server_error is None, run.server_error
    assert run.client_error is None, run.client_error
    assert run.server.established
    assert run.server.peer_certificates == client.chain
    assert run.server.client_certificate_verified


def test_an_rsa_client_authenticates(tmp_path):
    """RSA at 1.3 is PSS only (RFC 8446 4.4.3), and a verifier that
    accepted the PKCS#1 codepoints would take a signature OpenSSL will
    never make - so this passing is only half the statement. The other
    half is `test_the_pkcs1_schemes_are_not_offered`."""
    client = ClientIdentity(tmp_path, kind="rsa")
    run = OurServer(client_identity=client,
                    request_client_certificate=True,
                    require_client_certificate=True,
                    client_roots=client.roots()).pump()

    assert run.server_error is None, run.server_error
    assert run.server.established
    assert run.server.peer_certificates == client.chain


def test_an_optional_request_lets_a_client_with_nothing_through(tmp_path):
    """An empty Certificate is a legal answer (RFC 8446 4.4.2.1).

    This is the shape that goes wrong quietly: the server asked, got
    nothing, and carried on - which is correct, and is also what a
    caller who reads "asked" as "got" will treat as an authenticated
    connection. `peer_certificates` being empty is the only thing that
    says otherwise, so it is asserted rather than assumed.
    """
    run = OurServer(request_client_certificate=True).pump()
    assert run.server_error is None, run.server_error
    assert run.server.established
    assert run.server.peer_certificates == []
    assert not run.server.client_certificate_verified


def test_a_required_certificate_that_is_absent_is_refused(tmp_path):
    run = OurServer(request_client_certificate=True,
                    require_client_certificate=True).pump()
    assert not run.server.established
    assert run.server_error is not None
    assert "certificate" in str(run.server_error).lower()


def test_a_chain_from_another_ca_is_refused(tmp_path):
    """The signature is fine and the chain is not.

    The client holds the key for the certificate it sent - our signature
    check passes - and the certificate is issued by a CA this server was
    not told about. Refusing here is the whole point of `client_roots`
    being a separate set, and a server that verified against its own
    roots instead would accept anything with a public certificate.
    """
    client = ClientIdentity(tmp_path)
    stranger = ClientIdentity(tmp_path)
    run = OurServer(client_identity=client,
                    request_client_certificate=True,
                    require_client_certificate=True,
                    client_roots=stranger.roots()).pump()
    assert not run.server.established
    assert run.server_error is not None


def test_a_certificate_for_server_auth_only_is_refused(tmp_path):
    """extendedKeyUsage is not decoration.

    A server's own certificate is a certificate its operator holds the
    key for, so without this check a service could authenticate as a
    client to any peer trusting the same CA.
    """
    client = ClientIdentity(tmp_path,
                            eku=(ExtendedKeyUsageOID.SERVER_AUTH,))
    run = OurServer(client_identity=client,
                    request_client_certificate=True,
                    require_client_certificate=True,
                    client_roots=client.roots()).pump()
    assert not run.server.established
    assert run.server_error is not None
    assert "extendedKeyUsage" in str(run.server_error)


def test_a_server_that_does_not_ask_gets_nothing(tmp_path):
    """A client with a certificate loaded does not volunteer it.

    Which is the reason the request exists: sending a certificate
    unasked would hand every server the client's identity.
    """
    client = ClientIdentity(tmp_path)
    run = OurServer(client_identity=client).pump()
    assert run.server.established
    assert run.server.peer_certificates == []


def test_requiring_without_asking_is_refused(tmp_path):
    """Not a stricter setting - a contradiction.

    Nothing would ask the client, so nothing would arrive, and every
    handshake would fail at a check for a message never requested.
    """
    key, certificate = ec_identity()
    with pytest.raises(ValueError):
        allcrypt.TlsServer([certificate.public_bytes(DER)], key,
                           require_client_certificate=True, now=NOW)


def test_verifying_a_client_chain_needs_a_clock(tmp_path):
    """Without `now` every certificate is "not yet valid", which reads
    as the client's fault at a point far from the missing argument."""
    client = ClientIdentity(tmp_path)
    key, certificate = ec_identity()
    with pytest.raises(ValueError):
        allcrypt.TlsServer([certificate.public_bytes(DER)], key,
                           request_client_certificate=True,
                           client_roots=client.roots())


# ------------------------------------------- our client, OpenSSL's server ---

class OurClient:
    """Our client and an OpenSSL server, over memory BIOs.

    The mirror image, and the half our own server cannot judge: it makes
    the same choices we do about the context string, the transcript and
    the scheme, so it would accept our CertificateVerify however wrong
    it was.
    """

    def __init__(self, tmp_path, *, client_identity=None, mode=ssl.CERT_REQUIRED,
                 client_roots_pem=None, server_identity=None, version=TLS13):
        key, certificate = server_identity if server_identity else _server_pair()
        server_pem = tmp_path / "server.pem"
        server_pem.write_bytes(
            certificate.public_bytes(PEM)
            + key.private_bytes(PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = version
        context.maximum_version = version
        context.load_cert_chain(str(server_pem))
        context.verify_mode = mode
        if client_roots_pem:
            context.load_verify_locations(cadata=client_roots_pem)

        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.server = context.wrap_bio(self.incoming, self.outgoing,
                                       server_side=True)

        roots = allcrypt.TrustStore()
        roots.add_pem(certificate.public_bytes(PEM).decode())
        name = {ssl.TLSVersion.TLSv1_2: "TLSv1.2", TLS13: "TLSv1.3"}[version]
        options = dict(now=NOW, min_version=name, max_version=name)
        if client_identity is not None:
            options["client_certificate"] = client_identity.chain
            options["client_key"] = client_identity.ours
        self.client = allcrypt.TlsClient("localhost", roots, **options)
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


def _server_pair():
    """A server certificate `ssl` will accept for "localhost"."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(3)
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=3650))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                  critical=True)
                   .add_extension(usage(digital_signature=True,
                                        key_cert_sign=True, crl_sign=True),
                                  critical=True)
                   .add_extension(x509.ExtendedKeyUsage(
                       [ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .add_extension(x509.SubjectAlternativeName(
                       [x509.DNSName("localhost")]), critical=False)
                   .sign(key, hashes.SHA256()))
    return key, certificate


def test_we_authenticate_to_an_openssl_server(tmp_path):
    """The one that matters for our client.

    OpenSSL recomputed the transcript, applied the *client's* context
    string, and checked our signature against the certificate we sent.
    Our own server would have agreed with us whatever we did.
    """
    client = ClientIdentity(tmp_path)
    run = OurClient(tmp_path, client_identity=client,
                    client_roots_pem=client.ca_pem).pump()

    assert run.client_error is None, run.client_error
    assert run.server_error is None, run.server_error
    assert run.client.established
    assert run.server.getpeercert(True) == client.chain[0]


def test_we_authenticate_with_an_rsa_key(tmp_path):
    """PSS, because 1.3 has nothing else for RSA - and OpenSSL is what
    says whether the PSS parameters are the ones it expects."""
    client = ClientIdentity(tmp_path, kind="rsa")
    run = OurClient(tmp_path, client_identity=client,
                    client_roots_pem=client.ca_pem).pump()

    assert run.client_error is None, run.client_error
    assert run.server_error is None, run.server_error
    assert run.client.established


def test_we_send_an_empty_certificate_when_we_have_none(tmp_path):
    """Silence would be wrong: the server waits for the message.

    `CERT_OPTIONAL` is the configuration that can tell the difference -
    under `CERT_REQUIRED` OpenSSL fails either way, so a client that
    said nothing at all would look identical.
    """
    run = OurClient(tmp_path, mode=ssl.CERT_OPTIONAL).pump()
    assert run.client_error is None, run.client_error
    assert run.server_error is None, run.server_error
    assert run.client.established
    assert run.server.getpeercert() in (None, {})


def test_a_client_that_was_not_asked_sends_no_certificate(tmp_path):
    client = ClientIdentity(tmp_path)
    run = OurClient(tmp_path, client_identity=client, mode=ssl.CERT_NONE).pump()
    assert run.client.established
    assert run.server.getpeercert(True) is None


def test_a_certificate_without_its_key_is_refused(tmp_path):
    """Either one alone is a mistake worth naming at the call.

    A chain with no key cannot sign; a key with no chain has nothing to
    send. Both would otherwise surface as a handshake failure.
    """
    client = ClientIdentity(tmp_path)
    roots = allcrypt.TrustStore()
    with pytest.raises(ValueError):
        allcrypt.TlsClient("localhost", roots, now=NOW,
                           client_certificate=client.chain)
    with pytest.raises(ValueError):
        allcrypt.TlsClient("localhost", roots, now=NOW,
                           client_key=client.ours)


# ------------------------------------------------- the same thing at 1.2 ---
#
# A different message and a different signature, which is why doing 1.3
# did not bring 1.2 with it:
#
#   * `CertificateRequest` carries **certificate types** and CA names as
#     bare fields, where the 1.3 message has only extensions;
#   * `CertificateVerify` signs `Hash(handshake_messages)` - the raw
#     concatenation - where 1.3 signs a context string and a transcript
#     hash, so a signature made the 1.3 way verifies against nothing;
#   * RSA signs with **PKCS#1 v1.5**, which RFC 8446 4.4.3 forbids at 1.3;
#   * the order differs: the Certificate goes *before* the
#     ClientKeyExchange and the CertificateVerify *after* it.
#
# Every one of those is invisible between our own two ends.

TLS12 = ssl.TLSVersion.TLSv1_2


def test_an_openssl_client_authenticates_at_tls12(tmp_path):
    """The one that matters for our 1.2 server.

    OpenSSL read our certificate types, picked a scheme from the list
    beside them, hashed the concatenation of every handshake message
    itself and signed that. Four things none of which our own client
    could disagree with us about.
    """
    client = ClientIdentity(tmp_path)
    run = OurServer(client_identity=client, version=TLS12,
                    request_client_certificate=True,
                    require_client_certificate=True,
                    client_roots=client.roots()).pump()

    assert run.server_error is None, run.server_error
    assert run.client_error is None, run.client_error
    assert run.server.established
    assert run.server.version() == "TLSv1.2"
    assert run.server.peer_certificates == client.chain
    assert run.server.client_certificate_verified


def test_an_rsa_client_authenticates_at_tls12(tmp_path):
    """RSA at 1.2 is PKCS#1 v1.5, which is the opposite of 1.3.

    A server that verified with PSS here would refuse every real 1.2
    client, and one that signed with PSS would be refused by every real
    1.2 server. Only a peer that is not us can say which we did.
    """
    client = ClientIdentity(tmp_path, kind="rsa")
    run = OurServer(client_identity=client, version=TLS12,
                    request_client_certificate=True,
                    require_client_certificate=True,
                    client_roots=client.roots()).pump()
    assert run.server_error is None, run.server_error
    assert run.server.established
    assert run.server.peer_certificates == client.chain


def test_an_optional_request_at_tls12_lets_an_empty_answer_through(tmp_path):
    """An empty Certificate is legal at 1.2 too (RFC 5246 7.4.6), and a
    client that sent one owes no CertificateVerify - which is the part
    that differs from "the server did not ask"."""
    run = OurServer(version=TLS12, request_client_certificate=True).pump()
    assert run.server_error is None, run.server_error
    assert run.server.established
    assert run.server.peer_certificates == []
    assert not run.server.client_certificate_verified


def test_a_required_certificate_that_is_absent_is_refused_at_tls12(tmp_path):
    run = OurServer(version=TLS12, request_client_certificate=True,
                    require_client_certificate=True).pump()
    assert not run.server.established
    assert run.server_error is not None


def test_a_chain_from_another_ca_is_refused_at_tls12(tmp_path):
    client = ClientIdentity(tmp_path)
    stranger = ClientIdentity(tmp_path)
    run = OurServer(client_identity=client, version=TLS12,
                    request_client_certificate=True,
                    require_client_certificate=True,
                    client_roots=stranger.roots()).pump()
    assert not run.server.established
    assert run.server_error is not None


def test_we_authenticate_to_an_openssl_server_at_tls12(tmp_path):
    """The one that matters for our 1.2 client.

    OpenSSL rebuilt the concatenation itself, hashed it with the scheme
    we named, and checked our signature against the certificate we sent
    - in a message order our own server would have accepted whatever we
    chose.
    """
    client = ClientIdentity(tmp_path)
    run = OurClient(tmp_path, client_identity=client,
                    client_roots_pem=client.ca_pem, version=TLS12).pump()

    assert run.client_error is None, run.client_error
    assert run.server_error is None, run.server_error
    assert run.client.established
    assert run.client.version() == "TLSv1.2"
    assert run.server.getpeercert(True) == client.chain[0]


def test_we_authenticate_with_an_rsa_key_at_tls12(tmp_path):
    client = ClientIdentity(tmp_path, kind="rsa")
    run = OurClient(tmp_path, client_identity=client,
                    client_roots_pem=client.ca_pem, version=TLS12).pump()
    assert run.client_error is None, run.client_error
    assert run.server_error is None, run.server_error
    assert run.client.established


def test_we_send_an_empty_certificate_at_tls12_when_we_have_none(tmp_path):
    run = OurClient(tmp_path, mode=ssl.CERT_OPTIONAL, version=TLS12).pump()
    assert run.client_error is None, run.client_error
    assert run.server_error is None, run.server_error
    assert run.client.established
    assert run.server.getpeercert() in (None, {})


def test_a_client_that_was_not_asked_sends_nothing_at_tls12(tmp_path):
    client = ClientIdentity(tmp_path)
    run = OurClient(tmp_path, client_identity=client, mode=ssl.CERT_NONE,
                    version=TLS12).pump()
    assert run.client.established
    assert run.server.getpeercert(True) is None


# ------------------------------------------- and again at TLS 1.0 and 1.1 ---
#
# A **third** construction, not a second version of the 1.2 one:
#
#   * the CertificateRequest has no signature-algorithm list at all - TLS
#     1.2 added that field, and before it there was nothing to negotiate
#     because the version fixes the construction;
#   * the CertificateVerify is a **bare signature** with no algorithm
#     field, so what was signed is decided by the key's type;
#   * an RSA signature is over `MD5(handshake_messages) ||
#     SHA1(handshake_messages)` - 36 bytes - with **no DigestInfo**;
#   * an ECDSA one is over the SHA-1 half alone, and handing a verifier
#     all 36 bytes truncates them to the group's width and checks
#     something nobody signed.
#
# Every one of those is silent when wrong between our own two ends.

LEGACY = [(ssl.TLSVersion.TLSv1, "TLSv1"),
          (ssl.TLSVersion.TLSv1_1, "TLSv1.1")]
LEGACY_CIPHERS = "AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:@SECLEVEL=0"


class LegacyServer(OurServer):
    """Our server at TLS 1.0 or 1.1, with an OpenSSL client.

    `@SECLEVEL=0` is what lets this OpenSSL speak these versions at all;
    without it the client refuses before a byte crosses.
    """

    def __init__(self, version, *, identity=None, client_identity=None,
                 **options):
        self.key, certificate = identity if identity else ec_identity()
        chain = [certificate.public_bytes(DER)]

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.set_ciphers(LEGACY_CIPHERS)
        context.minimum_version = version
        context.maximum_version = version
        context.load_verify_locations(
            cadata=certificate.public_bytes(PEM).decode())
        if client_identity is not None:
            context.load_cert_chain(str(client_identity.path))

        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.client = context.wrap_bio(self.incoming, self.outgoing,
                                       server_hostname="localhost")
        name = {ssl.TLSVersion.TLSv1: "TLSv1",
                ssl.TLSVersion.TLSv1_1: "TLSv1.1"}[version]
        options.setdefault("now", NOW)
        options.setdefault("min_version", name)
        options.setdefault("max_version", name)
        options.setdefault("ciphers", "legacy")
        self.server = allcrypt.TlsServer(chain, self.key, **options)
        self.client_error = None
        self.server_error = None


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
@pytest.mark.parametrize("version,name", LEGACY)
def test_an_openssl_client_authenticates_before_tls12(version, name, tmp_path):
    """The one that matters for our pre-1.2 server, with an EC key.

    OpenSSL signed the SHA-1 half of the transcript hash and sent a bare
    signature with no algorithm field. Our own client would have agreed
    with us about both.
    """
    client = ClientIdentity(tmp_path)
    run = LegacyServer(version, client_identity=client,
                       request_client_certificate=True,
                       require_client_certificate=True,
                       client_roots=client.roots()).pump()

    assert run.server_error is None, run.server_error
    assert run.client_error is None, run.client_error
    assert run.server.established
    assert run.server.version() == name
    assert run.server.peer_certificates == client.chain
    assert run.server.client_certificate_verified


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
@pytest.mark.parametrize("version,name", LEGACY)
def test_an_rsa_client_authenticates_before_tls12(version, name, tmp_path):
    """**The one with no DigestInfo.**

    An RSA signature here is over 36 bytes of MD5 and SHA-1 with the
    hash identifier omitted, because the version fixes the pair. Signing
    it the 1.2 way - a SHA-256 DigestInfo over a single hash - produces
    a block that never matches, and the same is true in reverse for a
    verifier. Nothing between our own two ends can tell.
    """
    client = ClientIdentity(tmp_path, kind="rsa")
    run = LegacyServer(version, client_identity=client,
                       request_client_certificate=True,
                       require_client_certificate=True,
                       client_roots=client.roots()).pump()

    assert run.server_error is None, run.server_error
    assert run.server.established
    assert run.server.peer_certificates == client.chain


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
@pytest.mark.parametrize("version,name", LEGACY)
def test_an_empty_answer_before_tls12(version, name, tmp_path):
    run = LegacyServer(version, request_client_certificate=True).pump()
    assert run.server_error is None, run.server_error
    assert run.server.established
    assert run.server.peer_certificates == []


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
@pytest.mark.parametrize("version,name", LEGACY)
def test_a_required_certificate_that_is_absent_is_refused_before_tls12(
        version, name, tmp_path):
    run = LegacyServer(version, request_client_certificate=True,
                       require_client_certificate=True).pump()
    assert not run.server.established
    assert run.server_error is not None


class LegacyClient(OurClient):
    """Our client at TLS 1.0 or 1.1, with an OpenSSL server."""

    def __init__(self, tmp_path, version, *, client_identity=None,
                 client_roots_pem=None):
        # `_server_pair` rather than a fresh builder: the certificate has
        # to cover "localhost", which is the name our client checks.
        private, certificate = _server_pair()
        identity = tmp_path / f"legacy-{version.value}.pem"
        identity.write_bytes(
            certificate.public_bytes(PEM)
            + private.private_bytes(PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.set_ciphers(LEGACY_CIPHERS)
        context.minimum_version = version
        context.maximum_version = version
        context.load_cert_chain(str(identity))
        context.verify_mode = ssl.CERT_REQUIRED
        if client_roots_pem:
            context.load_verify_locations(cadata=client_roots_pem)

        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.server = context.wrap_bio(self.incoming, self.outgoing,
                                       server_side=True)

        roots = allcrypt.TrustStore()
        roots.add_pem(certificate.public_bytes(PEM).decode())
        name = {ssl.TLSVersion.TLSv1: "TLSv1",
                ssl.TLSVersion.TLSv1_1: "TLSv1.1"}[version]
        options = dict(now=NOW, min_version=name, max_version=name,
                       ciphers="legacy")
        if client_identity is not None:
            options["client_certificate"] = client_identity.chain
            options["client_key"] = client_identity.ours
        self.client = allcrypt.TlsClient("localhost", roots, **options)
        self.client_error = None
        self.server_error = None


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
@pytest.mark.parametrize("version,name", LEGACY)
@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_we_authenticate_before_tls12(version, name, kind, tmp_path):
    """The one that matters for our pre-1.2 client.

    OpenSSL rebuilt the 36 bytes itself and checked a signature with no
    algorithm field against the certificate we sent - deciding from the
    key's type what construction to expect, exactly as we decided what
    to produce. Our own server would have agreed with us either way.
    """
    client = ClientIdentity(tmp_path, kind=kind)
    run = LegacyClient(tmp_path, version, client_identity=client,
                       client_roots_pem=client.ca_pem).pump()

    assert run.client_error is None, run.client_error
    assert run.server_error is None, run.server_error
    assert run.client.established
    assert run.client.version() == name
    assert run.server.getpeercert(True) == client.chain[0]
