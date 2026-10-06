"""EdDSA in TLS: `ed25519` (0x0807) and `ed448` (0x0808), at 1.3 and 1.2,
for server and client certificates, against OpenSSL.

Each end of this is the other's mistake, so every test has OpenSSL on
one side:

  * **The signature covers the message, not a digest of it.** At 1.3
    that is the 64-space-prefixed context string and transcript hash; at
    1.2 it is `client_random || server_random || params` for a
    ServerKeyExchange (RFC 8422 section 5.4) and the raw handshake
    concatenation for a CertificateVerify (section 5.10). Every other
    scheme hashes first. Signing the digest instead is self-consistent
    between two ends that both do it, and verifies against nobody.
  * **There is no hash to negotiate.** The hash byte is 8, "Intrinsic",
    so `SignatureScheme::hash_name` answers `None` and a path that
    consults it before checking for EdDSA refuses the scheme. That was
    the 1.2 bug: the client offered `ed25519` in every hello and refused
    a 1.2 server that chose it.
  * **The signature is raw bytes**, 64 or 114, not a DER `SEQUENCE`.
  * **Ed448's context is empty.** RFC 8032 lets it carry one; TLS gives
    it none at either version.

At 1.2 an EdDSA key authenticates an ECDHE_ECDSA suite (RFC 8422
section 2 calls the exchange "Ephemeral ECDH with ECDSA or EdDSA
signatures"), and a client with an EdDSA certificate answers a request
for `ecdsa_sign` (section 3). Before 1.2 there is no EdDSA at all.
"""

import datetime
import ssl
import time

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import allcrypt

from test_tls_handshake import Handshake as ClientHandshake
from test_tls_server import Handshake as ServerHandshake, usage
from test_tls13_client_auth import (ClientIdentity, LegacyClient, OurClient,
                                    OurServer)

NOW = int(time.time())
TLS12 = ssl.TLSVersion.TLSv1_2
TLS13 = ssl.TLSVersion.TLSv1_3
NAMES = {TLS12: "TLSv1.2", TLS13: "TLSv1.3"}

CURVES = ["ed25519", "ed448"]
VERSIONS = [TLS12, TLS13]
KEY_CLASSES = {"ed25519": ed25519.Ed25519PrivateKey,
               "ed448": ed448.Ed448PrivateKey}


def eddsa_identity(curve="ed25519", common_name="localhost", sans=("localhost",)):
    """An EdDSA key from `cryptography`, its self-signed certificate, and
    the same key as an `allcrypt.EddsaKey`.

    The seed crosses over as bytes, so our end signs with the key OpenSSL
    checks against the certificate. Two independently generated keys
    would fail the handshake for a reason that says nothing.
    """
    key = KEY_CLASSES[curve].generate()
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
               .add_extension(
                   x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                   critical=False)
               .add_extension(
                   x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]),
                   critical=False))
    # EdDSA certificates are signed with no hash argument; `cryptography`
    # raises if one is given, as this library's builder refuses one.
    certificate = builder.sign(key, None)
    seed = key.private_bytes(serialization.Encoding.Raw,
                             serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    return key, certificate, allcrypt.EddsaKey.from_private(curve, seed)


# ------------------------------------------- our server, OpenSSL's client ---

@pytest.mark.parametrize("curve", CURVES)
@pytest.mark.parametrize("version", VERSIONS, ids=["tls12", "tls13"])
def test_an_openssl_client_accepts_our_eddsa_server(curve, version):
    """OpenSSL verified the signature our server made: the 1.3
    CertificateVerify, or the 1.2 ServerKeyExchange."""
    key, certificate, ours = eddsa_identity(curve)
    handshake = ServerHandshake(identity=(ours, certificate),
                                client_min=version, client_max=version, now=NOW)
    handshake.pump()
    assert handshake.server_error is None, handshake.server_error
    assert handshake.client_error is None, handshake.client_error
    assert handshake.server.established
    assert handshake.client.version() == NAMES[version]
    peer = x509.load_der_x509_certificate(
        handshake.client.getpeercert(binary_form=True))
    assert isinstance(peer.public_key(), type(key.public_key()))
    # Application data is what says each side accepted the other's
    # Finished under the agreed keys.
    assert handshake.send_from_client(b"hello") == b"hello"
    assert handshake.send_from_server(b"there") == b"there"


def test_at_tls12_an_eddsa_server_picks_an_ecdhe_ecdsa_suite():
    """RFC 8422 section 2: an EdDSA key authenticates ECDHE_ECDSA."""
    _, certificate, ours = eddsa_identity()
    handshake = ServerHandshake(identity=(ours, certificate),
                                client_min=TLS12, client_max=TLS12, now=NOW)
    handshake.pump()
    assert handshake.server.established
    assert "ECDHE-ECDSA" in handshake.client.cipher()[0]


def test_at_tls12_an_eddsa_server_refuses_a_suite_it_cannot_sign():
    """No suite but ECDHE_ECDSA is something an EdDSA key can sign for:
    not ECDHE_RSA, DHE_RSA, or RSA key transport. The refusal is at
    suite selection, where the cause is."""
    _, certificate, ours = eddsa_identity()
    handshake = ServerHandshake(identity=(ours, certificate),
                                client_ciphers="ECDHE-RSA-AES128-GCM-SHA256:"
                                               "DHE-RSA-AES128-GCM-SHA256:"
                                               "AES128-GCM-SHA256",
                                client_min=TLS12, client_max=TLS12,
                                ciphers="all", now=NOW)
    handshake.pump()
    assert not handshake.server.established
    assert "cannot authenticate" in str(handshake.server_error)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_before_tls12_an_eddsa_server_refuses():
    """No TLS 1.0 or 1.1 signature is defined for EdDSA."""
    _, certificate, ours = eddsa_identity()
    handshake = ServerHandshake(identity=(ours, certificate),
                                client_ciphers="ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0",
                                client_min=ssl.TLSVersion.TLSv1_1,
                                client_max=ssl.TLSVersion.TLSv1_1,
                                min_version="TLSv1.0", now=NOW)
    handshake.pump()
    assert not handshake.server.established
    assert "cannot authenticate" in str(handshake.server_error)


# ------------------------------------------- our client, OpenSSL's server ---

@pytest.mark.parametrize("curve", CURVES)
@pytest.mark.parametrize("version", VERSIONS, ids=["tls12", "tls13"])
def test_our_client_verifies_an_openssl_eddsa_server(curve, version):
    key, certificate, _ = eddsa_identity(curve)
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    handshake = ClientHandshake(key=key, certificate=certificate, ciphers=None,
                                server_min=version, server_max=version,
                                roots_pem=pem)
    try:
        handshake.pump()
        assert handshake.client_error is None, handshake.client_error
        assert handshake.client.established
        assert handshake.send(b"hello") == b"hello"
        assert handshake.receive(b"there") == b"there"
    finally:
        handshake.cleanup()


@pytest.mark.parametrize("curve", CURVES)
def test_a_tls12_only_hello_offers_eddsa(curve):
    """The 1.2 hello carries its own `signature_algorithms` list, apart
    from the 1.3 one. Without EdDSA in it, an EdDSA server reached by a
    1.2-only client has nothing to sign with."""
    key, certificate, _ = eddsa_identity(curve)
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    handshake = ClientHandshake(key=key, certificate=certificate, ciphers=None,
                                server_min=TLS12, server_max=TLS12,
                                roots_pem=pem, max_version="TLSv1.2")
    try:
        handshake.pump()
        assert handshake.client_error is None, handshake.client_error
        assert handshake.client.established
    finally:
        handshake.cleanup()


def test_we_offer_both_eddsa_schemes():
    """A scheme we verify and do not offer is unreachable, and the
    failure would say `handshake_failure`, which reads as a suite
    problem."""
    offered = allcrypt.tls_signature_schemes()
    assert "ed25519" in offered
    assert "ed448" in offered


# ----------------------------------------------------- client certificates ---

@pytest.mark.parametrize("curve", CURVES)
@pytest.mark.parametrize("version", VERSIONS, ids=["tls12", "tls13"])
def test_an_openssl_client_authenticates_with_eddsa(curve, version, tmp_path):
    """Our server verified OpenSSL's EdDSA CertificateVerify: at 1.2
    over the raw handshake concatenation, at 1.3 over the context
    string and transcript hash."""
    client = ClientIdentity(tmp_path, kind=curve)
    run = OurServer(client_identity=client, version=version,
                    request_client_certificate=True,
                    require_client_certificate=True,
                    client_roots=client.roots()).pump()
    assert run.server_error is None, run.server_error
    assert run.client_error is None, run.client_error
    assert run.server.established
    assert run.server.peer_certificates == client.chain
    assert run.server.client_certificate_verified


@pytest.mark.parametrize("curve", CURVES)
@pytest.mark.parametrize("version", VERSIONS, ids=["tls12", "tls13"])
def test_we_authenticate_with_eddsa(curve, version, tmp_path):
    """OpenSSL verified our EdDSA CertificateVerify. At 1.2 that also
    settles the certificate type: we answered `ecdsa_sign`."""
    client = ClientIdentity(tmp_path, kind=curve)
    run = OurClient(tmp_path, client_identity=client,
                    client_roots_pem=client.ca_pem, version=version).pump()
    assert run.client_error is None, run.client_error
    assert run.server_error is None, run.server_error
    assert run.client.established
    assert run.server.getpeercert(True) == client.chain[0]


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_before_tls12_we_answer_with_an_empty_certificate(tmp_path):
    """An EdDSA key cannot sign a 1.0 or 1.1 CertificateVerify, so the
    client sends an empty Certificate and the server decides. The
    refusal is the server's, for a missing certificate, not a local
    error from trying to sign."""
    client = ClientIdentity(tmp_path, kind="ed25519")
    run = LegacyClient(tmp_path, ssl.TLSVersion.TLSv1_1, client_identity=client,
                       client_roots_pem=client.ca_pem).pump()
    assert not run.client.established
    assert "PEER_DID_NOT_RETURN_A_CERTIFICATE" in str(run.server_error)
