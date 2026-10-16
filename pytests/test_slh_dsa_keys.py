"""SLH-DSA keys and certificates (RFC 9909) through the Python bindings:
RFC 9909's Appendix C, read out of the vendored text, and the IETF
hackathon's certificates and keys from four other implementations in
`vectors/slh_dsa_x509.vec` (`scripts/make_slh_dsa_x509_vectors.py`)."""

import base64
import pathlib
import re

import pytest

import allcrypt

ROOT = pathlib.Path(__file__).resolve().parent.parent
RFC = (ROOT / "rfcs" / "rfc9909.txt").read_text()
VECTORS = (ROOT / "vectors" / "slh_dsa_x509.vec").read_text()
SET = "SLH-DSA-SHA2-128s"


def appendix_blocks(label):
    """The DER of each PEM block in Appendix C with this label, page
    furniture dropped by keeping only base64 lines."""
    text = RFC[RFC.index("\nAppendix C.  Examples\n"):RFC.index("\nAcknowledgments\n")]
    blocks = []
    lines = iter(text.splitlines())
    for line in lines:
        if line.strip() == f"-----BEGIN {label}-----":
            body = []
            for inner in lines:
                inner = inner.strip()
                if inner == f"-----END {label}-----":
                    break
                if re.fullmatch(r"[A-Za-z0-9+/=]{1,64}", inner):
                    body.append(inner)
            blocks.append(base64.b64decode("".join(body)))
    return blocks


def records():
    text = VECTORS[VECTORS.index("\n[certificate]\n") + len("\n[certificate]\n"):]
    return [dict(line.split(" = ", 1) for line in chunk.splitlines())
            for chunk in text.strip().split("\n\n")]


def test_rfc_9909s_example_key_three_ways():
    [spki] = appendix_blocks("PUBLIC KEY")
    [private] = appendix_blocks("PRIVATE KEY")
    [certificate] = appendix_blocks("CERTIFICATE")
    key = allcrypt.private_key(private)
    assert isinstance(key, allcrypt.SlhDsaKey)
    assert key.parameter_set == SET and key.pre_hash is None
    assert key.recompute_public()
    public = allcrypt.SlhDsaPublicKey.from_spki(spki)
    assert public.parameter_set == SET and public.pre_hash is None
    assert public.public_bytes() == key.public_bytes()
    assert allcrypt.SlhDsaPublicKey.from_certificate(certificate).public_bytes() == \
        key.public_bytes()
    assert allcrypt.Certificate(certificate).to_dict()["publicKeyType"] == SET
    pem = allcrypt.pem_wrap(private, "PRIVATE KEY")
    assert allcrypt.private_key(pem.encode()).private_bytes() == key.private_bytes()


def test_a_hash_slh_dsa_key_comes_back_bound_to_its_pre_hash():
    [record] = [r for r in records()
                if r["provider"] == "bc" and r["name"] == "slh-dsa-sha2-128f-with-sha256"]
    key = allcrypt.private_key(base64.b64decode(record["private"]))
    assert isinstance(key, allcrypt.SlhDsaKey)
    assert (key.parameter_set, key.pre_hash) == ("SLH-DSA-SHA2-128f", "SHA2-256")
    public = allcrypt.SlhDsaPublicKey.from_certificate(base64.b64decode(record["certificate"]))
    assert public.pre_hash == "SHA2-256"
    assert public.public_bytes() == key.public_bytes()
    signature = key.sign(b"message", prehash=key.pre_hash)
    assert public.verify(b"message", signature, prehash=public.pre_hash)
    assert not public.verify(b"message", signature)


def test_every_hackathon_key_reads_as_its_certificates():
    rows = records()
    assert len(rows) == 56
    for row in rows:
        key = allcrypt.private_key(base64.b64decode(row["private"]))
        certificate = base64.b64decode(row["certificate"])
        public = allcrypt.SlhDsaPublicKey.from_certificate(certificate)
        assert key.parameter_set == public.parameter_set, row["name"]
        assert key.public_bytes() == public.public_bytes(), row["name"]


def test_a_ca_with_an_slh_dsa_key():
    ca = allcrypt.CertificateAuthority("SLH-DSA CA", "20260101000000Z", "20360101000000Z",
                                       key_type="SLH-DSA-SHAKE-128f")
    assert allcrypt.Certificate(ca.certificate).to_dict()["publicKeyType"] == \
        "SLH-DSA-SHAKE-128f"
    leaf, private = ca.issue("slh-dsa.example", "20260101000000Z", "20360101000000Z")
    info = allcrypt.Certificate(leaf).to_dict()
    assert info["publicKeyType"] == "SLH-DSA-SHAKE-128f"
    assert info["keyUsage"] == ["digitalSignature"]
    again = allcrypt.CertificateAuthority.from_parts(ca.private_bytes, ca.certificate,
                                                     key_type="SLH-DSA-SHAKE-128f")
    assert again.certificate == ca.certificate


def test_a_signing_key_is_not_an_slh_dsa_key():
    ca = allcrypt.CertificateAuthority("ML-DSA CA", "20260101000000Z", "20360101000000Z",
                                       key_type="ML-DSA-44")
    with pytest.raises(ValueError, match="not an SLH-DSA"):
        allcrypt.SlhDsaPublicKey.from_certificate(ca.certificate)
