"""Post-quantum keys written through the Python bindings: OpenSSL 3.5's
keys (`vectors/ml_dsa_openssl.vec`, `vectors/ml_kem_openssl.vec`) and the
IETF hackathon's SLH-DSA keys (`vectors/slh_dsa_x509.vec`) read and
written again come out as the files they came from."""

import base64
import pathlib

import pytest

import allcrypt

ROOT = pathlib.Path(__file__).resolve().parent.parent
FORMS = {"seed-only": "seed", "priv-only": "expanded", "seed-priv": "both"}


def records(name, section):
    text = (ROOT / "vectors" / name).read_text()
    text = text[text.index(f"\n[{section}]\n") + len(section) + 3:].split("\n[", 1)[0]
    return [dict(line.split(" = ", 1) for line in chunk.splitlines())
            for chunk in text.strip().split("\n\n")]


@pytest.mark.parametrize("file", ["ml_dsa_openssl.vec", "ml_kem_openssl.vec"])
def test_openssls_keys_written_again(file):
    keys = records(file, "key")
    assert len(keys) == 3
    for record in keys:
        for read_form in FORMS:
            key = allcrypt.private_key(base64.b64decode(record[read_form]))
            for write_form, form in FORMS.items():
                if read_form == "priv-only" and form != "expanded":
                    with pytest.raises(ValueError, match="no seed"):
                        key.to_pkcs8(form)
                    continue
                assert key.to_pkcs8(form) == base64.b64decode(record[write_form]), \
                    (record["name"], read_form, write_form)
                assert key.to_pkcs8(write_form) == key.to_pkcs8(form)
            assert key.public_key().to_spki() == base64.b64decode(record["public"])


def test_the_hackathons_slh_dsa_keys_written_again():
    rows = records("slh_dsa_x509.vec", "certificate")
    assert len(rows) == 56
    for row in rows:
        private = base64.b64decode(row["private"])
        assert allcrypt.private_key(private).to_pkcs8() == private, row["name"]
        public = allcrypt.SlhDsaPublicKey.from_certificate(base64.b64decode(row["certificate"]))
        assert allcrypt.SlhDsaPublicKey.from_spki(public.to_spki()).public_bytes() == \
            public.public_bytes()


def test_ml_dsa_public_keys_read_from_spki_and_certificates():
    for record in records("ml_dsa_openssl.vec", "certificate")[:1]:
        certificate = base64.b64decode(record[next(k for k in record if k != "name")])
        public = allcrypt.MlDsaPublicKey.from_certificate(certificate)
        assert allcrypt.MlDsaPublicKey.from_spki(public.to_spki()).public_bytes() == \
            public.public_bytes()
    with pytest.raises(ValueError, match="not an ML-DSA"):
        allcrypt.MlDsaPublicKey.from_spki(
            allcrypt.MlKemKey.generate("ML-KEM-512").public_key().to_spki())


def test_a_written_key_round_trips_and_encrypts():
    for key in [allcrypt.MlDsaKey.generate("ML-DSA-44"),
                allcrypt.MlKemKey.generate("ML-KEM-512"),
                allcrypt.SlhDsaKey.generate("SLH-DSA-SHAKE-128f")]:
        der = key.to_pkcs8()
        assert allcrypt.private_key(der).private_bytes() == key.private_bytes()
        pem = allcrypt.pem_wrap(der, "PRIVATE KEY")
        assert allcrypt.private_key(pem.encode()).private_bytes() == key.private_bytes()
        encrypted = allcrypt.encrypt_private_key(der, b"pw", "aes-256-cbc", iterations=1000)
        assert allcrypt.private_key(encrypted, b"pw").private_bytes() == key.private_bytes()


def test_the_seed_is_kept_where_there_is_one():
    seed = bytes(range(64))
    key = allcrypt.MlKemKey.from_seed("ML-KEM-768", seed)
    assert key.seed() == seed
    assert allcrypt.MlKemKey.from_private("ML-KEM-768", key.private_bytes()).seed() is None
    with pytest.raises(ValueError, match="not a private key form"):
        key.to_pkcs8("compact")
