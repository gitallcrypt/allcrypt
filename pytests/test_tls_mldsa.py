"""ML-DSA certificates (RFC 9881) and TLS 1.3 signatures
(draft-ietf-tls-mldsa, schemes 0x0904 to 0x0906).

**What these tests establish and what they cannot.** The OpenSSL these
tests run against is 3.0 and has no ML-DSA, and neither has
python-cryptography, so every handshake here is our client talking to our
server: that settles the wiring - which scheme each end picks, that the
1.2 paths refuse, that a client certificate goes out and is checked -
and nothing about whether the bytes are anybody else's.

That half is elsewhere. `src/x509/rfc9881_tests.rs` reads RFC 9881's own
examples; `tests/test_ml_dsa_openssl.rs` reads keys, certificates,
signatures and three real handshakes OpenSSL 3.5 produced, checking
OpenSSL's CertificateVerify with the function both our ends use; and
`scripts/check_mldsa_witness.py` puts OpenSSL 3.5 at the other end of a
live connection in both directions, by hand.
"""

import pathlib
import time

import pytest

import allcrypt

NOW = int(time.time())
VALID = ("20250101000000Z", "20350101000000Z")
SETS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
VECTORS = pathlib.Path(__file__).resolve().parent.parent / "vectors" / "ml_dsa_openssl.vec"


def ca_for(parameter_set):
    return allcrypt.CertificateAuthority("allcrypt ML-DSA test CA", *VALID,
                                         key_type=parameter_set)


class Ours:
    """Our client and our server, over memory, with an ML-DSA certificate
    our CA issued."""

    def __init__(self, parameter_set, client_max="TLSv1.3", server_max="TLSv1.3",
                 client_identity=None, request_client_certificate=False):
        ca = ca_for(parameter_set)
        leaf, seed = ca.issue("localhost", *VALID)
        self.key = allcrypt.MlDsaKey.from_seed(parameter_set, seed)
        roots = allcrypt.TrustStore()
        roots.add_pem(ca.certificate_pem)
        client_roots = None
        if request_client_certificate:
            client_roots = allcrypt.TrustStore()
            client_roots.add_pem(ca.certificate_pem)
        extra = {}
        if client_identity:
            certificate, key = client_identity(ca)
            extra = dict(client_certificate=[certificate], client_key=key)
        self.server = allcrypt.TlsServer([leaf], self.key, now=NOW, max_version=server_max,
                                         request_client_certificate=request_client_certificate,
                                         client_roots=client_roots)
        self.client = allcrypt.TlsClient("localhost", roots, now=NOW, min_version="TLSv1.2",
                                         max_version=client_max, **extra)
        self.error = None

    def pump(self, rounds=20):
        try:
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
        except Exception as error:  # noqa: BLE001 - the tests read it
            self.error = error
        return self


@pytest.mark.parametrize("parameter_set", SETS)
def test_our_client_and_server_authenticate_with_ml_dsa(parameter_set):
    run = Ours(parameter_set).pump()
    assert run.error is None, run.error
    assert run.client.established and run.server.established
    assert run.client.version() == "TLSv1.3"
    assert run.client.certificate_verified
    # Data after the handshake: the peer accepted our Finished under the
    # application keys, not merely a Finished that matched.
    run.client.write(b"signed by a lattice")
    run.server.push_incoming(run.client.take_outgoing())
    run.server.process()
    assert run.server.take_incoming() == b"signed by a lattice"


def test_an_ml_dsa_server_refuses_tls_1_2():
    """draft-ietf-tls-mldsa section 3.2: "MUST NOT be used in TLS 1.2". A
    1.2 client gets no suite, rather than one whose ServerKeyExchange this
    key would have to sign."""
    run = Ours("ML-DSA-44", client_max="TLSv1.2").pump()
    assert not run.client.established
    assert run.error is not None


def test_the_three_schemes_are_offered():
    offered = allcrypt.tls_signature_schemes()
    for name in ("mldsa44", "mldsa65", "mldsa87"):
        assert name in offered
    # After every classical scheme: a server that can do either should
    # not pick the one whose signature is kilobytes.
    assert offered.index("mldsa44") > offered.index("ed25519")


@pytest.mark.parametrize("parameter_set", ["ML-DSA-44", "ML-DSA-87"])
def test_an_ml_dsa_client_certificate_reaches_the_chain_check(parameter_set):
    """A client certificate with an ML-DSA key: the client signs its
    CertificateVerify and the server checks it.

    The CA here only issues `serverAuth` leaves, so the server refuses the
    chain for its purpose - and it checks the signature **before** the
    chain, so that refusal is only reachable through a CertificateVerify
    that verified. The full acceptance, with a certificate built for client
    authentication, is `tests/test_ml_dsa_tls13.rs`."""
    def identity(ca):
        leaf, seed = ca.issue("client.example", *VALID)
        return leaf, allcrypt.MlDsaKey.from_seed(parameter_set, seed)

    run = Ours(parameter_set, client_identity=identity,
               request_client_certificate=True).pump()
    assert "extendedKeyUsage" in str(run.error), run.error


def test_an_ml_dsa_client_key_that_is_not_the_certificates_is_refused():
    """The same handshake with a key the certificate does not hold fails at
    the signature, not at the chain - which is what makes the test above
    say something."""
    def identity(ca):
        leaf, _ = ca.issue("client.example", *VALID)
        return leaf, allcrypt.MlDsaKey.generate("ML-DSA-44")

    run = Ours("ML-DSA-44", client_identity=identity,
               request_client_certificate=True).pump()
    assert run.error is not None
    assert "extendedKeyUsage" not in str(run.error), run.error


def test_an_ml_dsa_client_certificate_is_withheld_at_tls_1_2():
    """A 1.2 server asking for a certificate gets an empty one rather than
    a CertificateVerify the key may not make."""
    def identity(ca):
        leaf, seed = ca.issue("client.example", *VALID)
        return leaf, allcrypt.MlDsaKey.from_seed("ML-DSA-44", seed)

    # The server's own key must work at 1.2, so it is EC here.
    ca = ca_for("ML-DSA-44")
    ec_ca = allcrypt.CertificateAuthority("allcrypt EC test CA", *VALID)
    leaf, scalar = ec_ca.issue("localhost", *VALID)
    roots = allcrypt.TrustStore()
    roots.add_pem(ec_ca.certificate_pem)
    server = allcrypt.TlsServer([leaf], allcrypt.EcKey.from_private("P-256", scalar),
                                now=NOW, max_version="TLSv1.2",
                                request_client_certificate=True)
    certificate, key = identity(ca)
    client = allcrypt.TlsClient("localhost", roots, now=NOW, max_version="TLSv1.2",
                                client_certificate=[certificate], client_key=key)
    for _ in range(20):
        out = client.take_outgoing()
        if out:
            server.push_incoming(out)
            server.process()
        back = server.take_outgoing()
        if back:
            client.push_incoming(back)
            client.process()
        if client.established and not out and not back:
            break
    assert server.established
    assert not server.peer_certificates


def test_the_ca_writes_rfc_9881_certificates():
    """What the CA puts in an ML-DSA certificate, read back by our parser
    and checked against RFC 9881 section 5: a leaf's key usage is
    digitalSignature and nothing that encrypts."""
    ca = ca_for("ML-DSA-65")
    leaf, seed = ca.issue("localhost", *VALID)
    assert len(seed) == 32
    info = allcrypt.Certificate(leaf).to_dict()
    assert info["publicKeyType"] == "ML-DSA-65"
    assert info["signatureAlgorithm"] == "ML-DSA-65"
    assert info["keyUsage"] == ["digitalSignature"]
    root = allcrypt.Certificate(ca.certificate).to_dict()
    assert set(root["keyUsage"]) == {"keyCertSign", "cRLSign"}
    # The CA comes back from its parts, and refuses a key it does not hold.
    again = allcrypt.CertificateAuthority.from_parts(ca.private_bytes, ca.certificate,
                                                     key_type="ML-DSA-65")
    assert again.certificate == ca.certificate
    with pytest.raises(ValueError):
        allcrypt.CertificateAuthority.from_parts(bytes(32), ca.certificate,
                                                 key_type="ML-DSA-65")


def openssl_key_pem(parameter_set, form):
    lines = VECTORS.read_text().splitlines()
    start = lines.index(f"name = {parameter_set}")
    for line in lines[start:]:
        if line.startswith(f"{form} = "):
            body = line.split(" = ", 1)[1]
            return "-----BEGIN PRIVATE KEY-----\n" + "\n".join(
                body[i:i + 64] for i in range(0, len(body), 64)) + \
                "\n-----END PRIVATE KEY-----\n"
    raise AssertionError(f"no {form} for {parameter_set}")


@pytest.mark.parametrize("form", ["seed-only", "priv-only", "seed-priv"])
def test_private_key_reads_every_form_openssl_writes(form):
    """`allcrypt.private_key` on OpenSSL 3.5's PEM gives an `MlDsaKey`,
    the same key whichever of RFC 9881's three forms the file used."""
    keys = {f: allcrypt.private_key(openssl_key_pem("ML-DSA-65", f).encode())
            for f in ("seed-only", "priv-only", "seed-priv")}
    key = keys[form]
    assert isinstance(key, allcrypt.MlDsaKey)
    assert key.parameter_set == "ML-DSA-65"
    assert key.public_bytes() == keys["seed-only"].public_bytes()
    assert (key.seed() is not None) == (form != "priv-only")
    signature = key.sign(b"message")
    assert keys["priv-only"].verify(b"message", signature)
