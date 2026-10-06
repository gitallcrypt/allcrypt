"""Ed25519 certificates, RFC 8410, against python-cryptography.

Both directions, because the two halves of this encoding are each
other's obvious mistake and would agree perfectly if both were wrong:

  * **The BIT STRING is the key.** Every other key in this library wraps
    something - RSA a SEQUENCE, EC a SEC1 point with a format byte, GOST
    an OCTET STRING of little endian coordinates. RFC 8410 section 4
    says the subjectPublicKey *is* the 32 bytes, and a parser written
    from the neighbouring branches looks for a structure that is not
    there.
  * **The parameters field must be absent, not NULL.** RSA writes an
    explicit NULL beside its OID and an encoder copied from it would
    write one here. Both encodings parse in plenty of software, so a
    round trip against ourselves would never notice.
  * **One OID is both the key algorithm and the signature algorithm.**
    There is no "Ed25519 with SHA-512" - the hash is inside the scheme.
  * **The signature is the raw 64 bytes**, not a DER SEQUENCE of two
    INTEGERs the way ECDSA's is.

So: certificates OpenSSL made, read here; certificates made here, read
and verified by python-cryptography.
"""

import subprocess
import time

import pytest

from cryptography import x509 as cx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import allcrypt


WINDOW = ("20260101000000Z", "20270101000000Z")
INSIDE = 1780000000  # a moment inside that window

def now():
    """The current second, read **when the check runs**.

    `openssl req -days 365` dates from now, so a certificate it makes is
    checked at the current time rather than at INSIDE. A module-level
    `NOW = int(time.time())` looked equivalent and was not: the whole
    suite takes the better part of a minute, so by the time this file
    ran, `NOW` was seconds *before* the certificate's own notBefore and
    the test failed with "not valid until" - passing on its own and
    failing in the suite, which is the worst shape a test comes in.
    """
    return int(time.time())


def openssl_self_signed(tmp_path, algorithm="ed25519"):
    """A self-signed certificate and its key, from the openssl binary."""
    key = tmp_path / f"{algorithm}.pem"
    cert = tmp_path / f"{algorithm}-cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", algorithm, "-keyout", str(key),
         "-out", str(cert), "-days", "365", "-nodes", "-subj", "/CN=openssl test"],
        capture_output=True, check=True)
    der = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-outform", "DER"],
        capture_output=True, check=True).stdout
    return der, key.read_bytes()


# ----------------------------------------------------- reading what OpenSSL wrote ---

def test_we_parse_an_openssl_ed25519_certificate(tmp_path):
    der, _ = openssl_self_signed(tmp_path)
    fields = allcrypt.Certificate(der).to_dict()
    assert fields["publicKeyType"] == "EdDSA ed25519"
    assert fields["signatureAlgorithm"] == "EdDSA (ed25519)"


def test_we_verify_an_openssl_ed25519_signature(tmp_path):
    der, _ = openssl_self_signed(tmp_path)
    # Self-signed, so it is its own root. What this checks is the
    # signature, which is the only part the parser cannot fake.
    allcrypt.verify_chain([der], [der], now())


def test_a_tampered_openssl_certificate_is_refused(tmp_path):
    der, _ = openssl_self_signed(tmp_path)
    for index in (-1, -33, len(der) // 2):
        altered = bytearray(der)
        altered[index] ^= 0x01
        with pytest.raises(ValueError):
            allcrypt.verify_chain([bytes(altered)], [der], now())


def test_we_load_an_openssl_ed25519_private_key(tmp_path):
    der, key_pem = openssl_self_signed(tmp_path)
    key = allcrypt.private_key(key_pem)
    assert key.curve == "ed25519"
    assert len(key.private_bytes()) == 32

    # The seed's public half must be the one in the certificate. A
    # parser that unwrapped the OCTET STRING once instead of twice gets
    # 34 bytes beginning `04 20` - the right length for nothing - so
    # this is what catches that.
    certificate = cx.load_der_x509_certificate(der)
    raw = certificate.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert key.public_bytes() == raw


def test_a_key_openssl_wrote_still_signs_for_its_certificate(tmp_path):
    der, key_pem = openssl_self_signed(tmp_path)
    key = allcrypt.private_key(key_pem)
    signature = key.sign(b"a message")
    certificate = cx.load_der_x509_certificate(der)
    certificate.public_key().verify(signature, b"a message")


# ------------------------------------------------- writing what OpenSSL can read ---

@pytest.fixture
def ca():
    return allcrypt.CertificateAuthority(
        "allcrypt ed25519 CA", *WINDOW, key_type="ed25519")


def test_the_ca_says_what_it_is(ca):
    assert ca.key_type == "ed25519"
    assert len(ca.private_bytes) == 32


def test_python_cryptography_reads_our_ca(ca):
    parsed = cx.load_der_x509_certificate(ca.certificate)
    assert isinstance(parsed.public_key(), ed25519.Ed25519PublicKey)
    assert parsed.subject.rfc4514_string() == "CN=allcrypt ed25519 CA"
    # Self-signed, and the signature checks out over there.
    parsed.public_key().verify(parsed.signature, parsed.tbs_certificate_bytes)


def test_python_cryptography_verifies_a_leaf_we_issued(ca):
    leaf_der, _ = ca.issue("example.test", *WINDOW)
    leaf = cx.load_der_x509_certificate(leaf_der)
    issuer = cx.load_der_x509_certificate(ca.certificate)

    assert isinstance(leaf.public_key(), ed25519.Ed25519PublicKey)
    assert leaf.issuer == issuer.subject
    # **The check that matters.** Everything above is the parser
    # agreeing with itself; this is somebody else's implementation
    # accepting bytes we produced.
    issuer.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes)


def test_the_leaf_key_we_hand_back_belongs_to_the_leaf(ca):
    leaf_der, private = ca.issue("example.test", *WINDOW)
    key = allcrypt.EddsaKey.from_private("ed25519", private)
    leaf = cx.load_der_x509_certificate(leaf_der)
    raw = leaf.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert key.public_bytes() == raw


def test_we_verify_our_own_chain(ca):
    leaf_der, _ = ca.issue("example.test", *WINDOW)
    allcrypt.verify_chain([leaf_der], [ca.certificate], INSIDE)


def test_a_leaf_from_another_ca_does_not_verify(ca):
    other = allcrypt.CertificateAuthority("other CA", *WINDOW, key_type="ed25519")
    leaf_der, _ = other.issue("example.test", *WINDOW)
    with pytest.raises(ValueError):
        allcrypt.verify_chain([leaf_der], [ca.certificate], INSIDE)


def test_the_algorithm_identifier_has_no_parameters(ca):
    """RFC 8410 section 3, checked at the bytes.

    An explicit NULL parses in most software, so no round trip and no
    verification anywhere would notice one. What would notice is a
    strict verifier, months later, on somebody else's machine - the
    same shape as the UTCTime/GeneralizedTime bug in pitfalls.md, which
    only handing a certificate to somebody else found.
    """
    parsed = cx.load_der_x509_certificate(ca.certificate)
    spki = parsed.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    # SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING }
    assert spki.hex().startswith("302a300506032b6570032100")
    assert len(spki) == 44
    assert spki in ca.certificate

    # The signature AlgorithmIdentifier too, which is a different place
    # in the file and a different function in the builder.
    algorithm = bytes.fromhex("300506032b6570")
    assert ca.certificate.count(algorithm) >= 2, \
        "the OID should appear in the SPKI and in both signature algorithm fields"


def test_our_signature_is_raw_bytes_not_a_der_sequence(ca):
    """ECDSA's certificate signature is `SEQUENCE { r, s }` and EdDSA's
    is the raw 64 bytes. They sit in the same field, and writing one
    where the other belongs produces something that parses."""
    parsed = cx.load_der_x509_certificate(ca.certificate)
    assert len(parsed.signature) == 64
    assert not parsed.signature.startswith(b"\x30")


def test_an_ed25519_ca_issues_ed25519_leaves(ca):
    leaf_der, _ = ca.issue("example.test", *WINDOW)
    assert allcrypt.Certificate(leaf_der).to_dict()["publicKeyType"] == "EdDSA ed25519"


def test_the_default_ca_is_still_p256():
    """The proxy generates one of these while a browser waits, and
    P-256 is the fastest generation here. Changing the default would be
    a latency change nobody asked for."""
    default = allcrypt.CertificateAuthority("default CA", *WINDOW)
    assert default.key_type == "P-256"


def test_a_ca_can_be_rebuilt_from_its_parts(ca):
    rebuilt = allcrypt.CertificateAuthority.from_parts(
        ca.private_bytes, ca.certificate, "ed25519")
    assert rebuilt.key_type == "ed25519"
    leaf_der, _ = rebuilt.issue("example.test", *WINDOW)
    allcrypt.verify_chain([leaf_der], [ca.certificate], INSIDE)


def test_a_mismatched_key_and_certificate_are_refused(ca):
    other = allcrypt.CertificateAuthority("other CA", *WINDOW, key_type="ed25519")
    with pytest.raises(ValueError, match="does not hold this key"):
        allcrypt.CertificateAuthority.from_parts(
            other.private_bytes, ca.certificate, "ed25519")


def test_an_ed25519_key_is_not_accepted_as_a_p256_one(ca):
    # The seed is 32 bytes and so is a P-256 scalar, so the length does
    # not separate them - only the certificate check does.
    with pytest.raises(ValueError):
        allcrypt.CertificateAuthority.from_parts(ca.private_bytes, ca.certificate)
