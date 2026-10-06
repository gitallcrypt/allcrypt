"""DSA: certificates (RFC 3279, RFC 5758), private keys, and the DHE_DSS
TLS suites, against OpenSSL.

DSA is what a switch, a UPS card or a storage controller from the 2000s
may have and nothing else: FIPS 186-5 withdrew it for new signatures in
2023, and OpenSSH removed `ssh-dss` in 2024. Every test here has OpenSSL
(through Python's `ssl` or python-cryptography) on the other side - a DSA
signature both ends of this library agree on says nothing about whether
anybody else does.
"""

import datetime
import shutil
import ssl
import subprocess
import time

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.x509.oid import NameOID

import allcrypt

from test_tls_handshake import Handshake

NOW = int(time.time())

# Group generation is the slow part of DSA, so each size is made once.
_KEYS = {}


def dsa_key(bits=2048):
    if bits not in _KEYS:
        _KEYS[bits] = dsa.generate_private_key(bits)
    return _KEYS[bits]


def certificate(key, hash_algorithm=None, common_name="localhost", issuer_key=None,
                issuer_name=None, ca=False):
    """A certificate for `key`, signed by `issuer_key` (itself by default)
    with `hash_algorithm`."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(issuer_name or name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=30))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]),
                              critical=False))
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                        critical=True)
    return builder.sign(issuer_key or key, hash_algorithm or hashes.SHA256())


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


# ------------------------------------------------------------ certificates ---

@pytest.mark.parametrize("algorithm", [hashes.SHA224(), hashes.SHA256(),
                                       hashes.SHA384(), hashes.SHA512()],
                         ids=lambda a: a.name)
def test_openssls_dsa_certificates_verify(algorithm):
    """A DSA root signing a DSA leaf with each SHA-2 hash RFC 5758 and
    NIST's arc give OIDs for, verified by our chain verifier."""
    root_key, leaf_key = dsa_key(2048), dsa.generate_private_key(2048)
    root = certificate(root_key, hashes.SHA256(), "DSA root", ca=True)
    leaf = certificate(leaf_key, algorithm, "localhost", issuer_key=root_key,
                       issuer_name=root.subject)
    allcrypt.verify_chain([der(leaf)], [der(root)], NOW, hostname="localhost")
    info = allcrypt.Certificate(der(leaf)).to_dict()
    assert info["publicKeyType"] == "DSA"
    assert info["publicKeyBits"] == 2048
    assert info["signatureAlgorithm"] == f"DSA with {algorithm.name}"


def test_a_dsa_with_sha1_certificate_needs_permission(tmp_path):
    """`dsaWithSHA1`, RFC 3279's own, which is what the old boxes have.
    python-cryptography will no longer sign one, so the `openssl` tool
    makes it. SHA-1 needs the caller's permission, as it does for RSA and
    ECDSA - and with it, the 1024 bit group needs the RSA floor lowered."""
    tool = shutil.which("openssl")
    if tool is None:
        pytest.skip("openssl is not installed")
    key_path, cert_path = tmp_path / "dsa.pem", tmp_path / "dsa.crt"
    subprocess.run([tool, "dsaparam", "-genkey", "-out", str(key_path), "1024"],
                   check=True, capture_output=True)
    subprocess.run([tool, "req", "-x509", "-key", str(key_path), "-sha1", "-subj",
                    "/CN=localhost", "-days", "3", "-outform", "DER", "-out",
                    str(cert_path)], check=True, capture_output=True)
    cert = cert_path.read_bytes()
    assert allcrypt.Certificate(cert).to_dict()["signatureAlgorithm"] == "DSA with sha1"
    # `req` starts the validity now, to the second.
    now = int(time.time()) + 60
    with pytest.raises(allcrypt.CryptoError, match="SHA-1"):
        allcrypt.verify_chain([cert], [cert], now, min_rsa_bits=1024)
    with pytest.raises(allcrypt.CryptoError, match="min_rsa_bits"):
        allcrypt.verify_chain([cert], [cert], now, allow_sha1=True)
    allcrypt.verify_chain([cert], [cert], now, allow_sha1=True, min_rsa_bits=1024)


def test_a_dsa_signature_under_the_wrong_key_is_refused():
    root_key = dsa_key(2048)
    root = certificate(root_key, hashes.SHA256(), "DSA root", ca=True)
    impostor = dsa.generate_private_key(2048)
    leaf = certificate(dsa.generate_private_key(2048), hashes.SHA256(), "localhost",
                       issuer_key=impostor, issuer_name=root.subject)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.verify_chain([der(leaf)], [der(root)], NOW, hostname="localhost")


def test_a_1024_bit_dsa_group_needs_the_rsa_floor_lowered():
    """The group is held to `min_rsa_bits`, which defaults to 2048: a
    1024 bit DSA group falls to the same effort as a 1024 bit modulus.
    Lowering the one number reaches the old box, as it does for RSA."""
    key = dsa_key(1024)
    cert = certificate(key, hashes.SHA256())
    with pytest.raises(allcrypt.CryptoError, match="min_rsa_bits"):
        allcrypt.verify_chain([der(cert)], [der(cert)], NOW)
    allcrypt.verify_chain([der(cert)], [der(cert)], NOW, min_rsa_bits=1024)


# ------------------------------------------------------------ private keys ---

@pytest.mark.parametrize("form", [serialization.PrivateFormat.PKCS8,
                                  serialization.PrivateFormat.TraditionalOpenSSL],
                         ids=["pkcs8", "traditional"])
def test_private_key_reads_openssls_dsa_files(form):
    """PKCS#8 and the traditional `DSA PRIVATE KEY`, which `openssl dsa`
    wrote for two decades. The key is then used: our signature verified by
    OpenSSL, and OpenSSL's by ours."""
    theirs = dsa_key(2048)
    pem = theirs.private_bytes(serialization.Encoding.PEM, form,
                               serialization.NoEncryption())
    ours = allcrypt.private_key(pem)
    assert isinstance(ours, allcrypt.DsaKey)
    numbers = theirs.private_numbers()
    assert int.from_bytes(ours.private_bytes(), "big") == numbers.x
    assert int.from_bytes(ours.public_bytes(), "big") == numbers.public_numbers.y
    assert ours.key_size == 2048

    message = b"signed with DSA"
    theirs.public_key().verify(ours.sign(message, "sha256"), message, hashes.SHA256())
    assert ours.verify(message, theirs.sign(message, hashes.SHA256()), "sha256")
    assert not ours.verify(message + b"!", theirs.sign(message, hashes.SHA256()), "sha256")


def test_a_traditional_key_whose_y_is_not_g_to_the_x_is_refused():
    """The traditional form stores `y` beside `x`; a file where they
    disagree signs as one key and claims another."""
    theirs = dsa_key(2048)
    der_key = theirs.private_bytes(serialization.Encoding.DER,
                                   serialization.PrivateFormat.TraditionalOpenSSL,
                                   serialization.NoEncryption())
    numbers = theirs.private_numbers()
    y = numbers.public_numbers.y.to_bytes((numbers.public_numbers.y.bit_length() + 7) // 8,
                                          "big")
    at = der_key.index(y)
    # The last byte of y, which cannot change the INTEGER's encoding.
    broken = der_key[:at + len(y) - 1] + bytes([y[-1] ^ 1]) + der_key[at + len(y):]
    with pytest.raises(allcrypt.CryptoError, match="g\\^x"):
        allcrypt.private_key(broken)


# --------------------------------------------------------------- DHE_DSS ---

@pytest.mark.parametrize("version, suite, expected", [
    (ssl.TLSVersion.TLSv1_2, "DHE-DSS-AES128-GCM-SHA256",
     "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"),
    (ssl.TLSVersion.TLSv1_2, "DHE-DSS-AES256-SHA256", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"),
    (ssl.TLSVersion.TLSv1_1, "DHE-DSS-AES128-SHA", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"),
    (ssl.TLSVersion.TLSv1, "DHE-DSS-AES256-SHA", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"),
], ids=["1.2-gcm", "1.2-cbc", "1.1", "1.0"])
def test_our_client_reaches_an_openssl_dhe_dss_server(version, suite, expected):
    """OpenSSL signs the ServerKeyExchange with its DSA key, and our client
    checks that signature: over SHA-1 alone before TLS 1.2 (RFC 4346
    7.4.3), with the hash the scheme names at 1.2."""
    key = dsa_key(2048)
    exchange = Handshake(key=key, certificate=certificate(key),
                         ciphers=f"{suite}:@SECLEVEL=0", server_max=version,
                         server_min=ssl.TLSVersion.TLSv1, server_dh_bits=2048,
                         min_version="TLSv1.0", max_version="TLSv1.2")
    try:
        exchange.pump()
        assert exchange.client_error is None, exchange.client_error
        assert exchange.client.established
        assert exchange.client.cipher()[0] == expected
        assert exchange.client.certificate_verified
        assert exchange.send(b"to an old box") == b"to an old box"
        assert exchange.receive(b"from an old box") == b"from an old box"
    finally:
        exchange.cleanup()


def test_dhe_dss_is_offered_with_its_signature_schemes():
    """The suites are in the default selection, and a scheme offered with no
    suite that can use it is a row nothing checks - so the DSA schemes are
    in the hello exactly when a DHE_DSS suite is."""
    assert any("DHE_DSS" in name for name in allcrypt.tls_suite_names("modern"))
    assert not any("DHE_DSS" in name and "3DES" in name
                   for name in allcrypt.tls_suite_names("modern"))
    assert any("DHE_DSS_WITH_3DES" in name for name in allcrypt.tls_suite_names("legacy"))
