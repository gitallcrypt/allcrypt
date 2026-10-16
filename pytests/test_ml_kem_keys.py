"""ML-KEM keys and certificates (RFC 9935) through the Python bindings:
RFC 9935's Appendix C, read out of the vendored text, and the keys,
encapsulations and certificates OpenSSL 3.5 wrote into
`vectors/ml_kem_openssl.vec` (`scripts/capture_mlkem.py`)."""

import base64
import pathlib
import re

import pytest

import allcrypt

ROOT = pathlib.Path(__file__).resolve().parent.parent
RFC = (ROOT / "rfcs" / "rfc9935.txt").read_text()
VECTORS = (ROOT / "vectors" / "ml_kem_openssl.vec").read_text()
SETS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]


def appendix_blocks(label):
    """`(section, der)` for each PEM block in Appendix C with this label,
    page furniture dropped by keeping only base64 lines."""
    text = RFC[RFC.index("\nAppendix C.  Examples\n"):RFC.index("\nAcknowledgments\n")]
    blocks, section = [], None
    lines = iter(text.splitlines())
    for line in lines:
        if line.startswith("C."):
            section = line.split()[0].rstrip(".")
        if line.strip() == f"-----BEGIN {label}-----":
            body = []
            for inner in lines:
                inner = inner.strip()
                if inner == f"-----END {label}-----":
                    break
                if re.fullmatch(r"[A-Za-z0-9+/=]{1,64}", inner):
                    body.append(inner)
            blocks.append((section, base64.b64decode("".join(body))))
    return blocks


def records(name):
    text = VECTORS[VECTORS.index(f"\n[{name}]\n") + len(name) + 3:]
    text = text.split("\n[", 1)[0]
    return [dict(line.split(" = ", 1) for line in chunk.splitlines())
            for chunk in text.strip().split("\n\n")]


def test_rfc_9935s_private_keys_come_back_as_ml_kem_keys():
    keys = [(s, der) for s, der in appendix_blocks("PRIVATE KEY") if s.startswith("C.1")]
    assert len(keys) == 9
    seed = bytes(range(64))
    for i, (section, der) in enumerate(keys):
        key = allcrypt.private_key(der)
        assert isinstance(key, allcrypt.MlKemKey), section
        assert key.parameter_set == SETS[i // 3]
        assert key.private_bytes() == \
            allcrypt.MlKemKey.from_seed(SETS[i // 3], seed).private_bytes()
        pem = allcrypt.pem_wrap(der, "PRIVATE KEY")
        assert allcrypt.private_key(pem.encode()).private_bytes() == key.private_bytes()


def test_rfc_9935s_bad_keys_are_refused():
    bad = [der for s, der in appendix_blocks("PRIVATE KEY") if s.startswith("C.4")]
    assert len(bad) == 4
    for der in bad:
        with pytest.raises(ValueError, match="ML-KEM-512"):
            allcrypt.private_key(der)


def test_rfc_9935s_public_keys_and_certificates():
    publics = appendix_blocks("PUBLIC KEY")
    certificates = appendix_blocks("CERTIFICATE")
    assert len(publics) == len(certificates) == 3
    seed = bytes(range(64))
    for (_, spki), (_, certificate), name in zip(publics, certificates, SETS):
        expected = allcrypt.MlKemKey.from_seed(name, seed).public_key().public_bytes()
        assert allcrypt.MlKemPublicKey.from_spki(spki).public_bytes() == expected
        from_certificate = allcrypt.MlKemPublicKey.from_certificate(certificate)
        assert from_certificate.parameter_set == name
        assert from_certificate.public_bytes() == expected


def test_openssls_encapsulations_decapsulate():
    keys = {r["name"]: r for r in records("key")}
    encapsulations = records("encapsulation")
    assert len(keys) == 3 and len(encapsulations) == 9
    for row in encapsulations:
        for form in ("seed-only", "priv-only", "seed-priv"):
            key = allcrypt.private_key(base64.b64decode(keys[row["name"]][form]))
            assert key.decapsulate(bytes.fromhex(row["ciphertext"])) == \
                bytes.fromhex(row["secret"]), (row["name"], form)


def test_a_certificate_for_openssls_key_round_trips():
    keys = records("key")
    ca = allcrypt.CertificateAuthority("ML-DSA CA", "20260101000000Z", "20360101000000Z",
                                       key_type="ML-DSA-44")
    for record in keys:
        public = allcrypt.MlKemPublicKey.from_spki(base64.b64decode(record["public"]))
        der = ca.issue_ml_kem("a key", public, "20260101000000Z", "20360101000000Z")
        info = allcrypt.Certificate(der).to_dict()
        assert info["publicKeyType"] == record["name"]
        assert info["keyUsage"] == ["keyEncipherment"]
        assert allcrypt.MlKemPublicKey.from_certificate(der).public_bytes() == \
            public.public_bytes()


def test_a_signing_key_is_not_an_ml_kem_key():
    certificate = records("certificate")[0]
    with pytest.raises(ValueError, match="not an ML-KEM"):
        allcrypt.MlKemPublicKey.from_certificate(base64.b64decode(certificate["ca"]))
