"""HSS, XMSS and XMSS^MT keys in certificates (RFC 9802) through the
Python bindings: RFC 9802's appendix certificates and Bouncy Castle's and
this library's from vectors/hbs_x509.vec, read into HashSigPublicKey;
keys made by HssKey and XmssKey written as a SubjectPublicKeyInfo and
read back; and the refusals."""

import os
import re

import pytest

import allcrypt

HERE = os.path.dirname(__file__)
VECTORS = os.path.join(HERE, "..", "vectors", "hbs_x509.vec")
RFC = os.path.join(HERE, "..", "rfcs", "rfc9802.txt")


def rows():
    with open(VECTORS) as f:
        return [dict(w.split("=", 1) for w in line.split()[1:]) | {"kind": line.split()[0]}
                for line in f if line[0] != "#"]


def appendix_pems():
    text = open(RFC, encoding="utf-8").read()
    text = text[text.index("Appendix A.  HSS X.509 v3 Certificate Example\n\n   This"):]
    return ["\n".join(l.strip() for l in block.splitlines())
            for block in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                                    text, re.S)]


def test_the_appendix_certificates():
    pems = appendix_pems()
    assert len(pems) == 3
    names = [("HSS", "HSS with 1 level, LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W8 on top"),
             ("XMSS", "XMSS-SHA2_10_256"), ("XMSS^MT", "XMSSMT-SHA2_20/2_256")]
    for pem, (scheme, name) in zip(pems, names):
        key = allcrypt.HashSigPublicKey.from_certificate(pem.encode())
        assert (key.scheme, key.parameter_set) == (scheme, name)
        assert allcrypt.HashSigPublicKey.from_spki(key.to_spki()).public_bytes() \
            == key.public_bytes()


def test_the_vector_certificates():
    count = 0
    for r in rows():
        key = allcrypt.HashSigPublicKey.from_certificate(bytes.fromhex(r["cert"]))
        multi = r["scheme"] == "xmssmt" or r.get("set", "").startswith("XMSSMT-")
        assert key.scheme == ("HSS" if r["scheme"] == "hss" else "XMSS^MT" if multi else "XMSS")
        if "set" in r:
            assert key.parameter_set == r["set"]
        count += 1
    assert count == 27


def test_keys_from_the_signing_classes():
    hss = allcrypt.HssKey.from_seed([("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8")], bytes(32),
                                    bytes(16))
    key = allcrypt.HashSigPublicKey.from_public("HSS", hss.public_bytes())
    signature = hss.sign(b"message")
    assert key.verify(b"message", signature) and not key.verify(b"other", signature)
    spki = key.to_spki()
    assert allcrypt.HashSigPublicKey.from_spki(spki).public_bytes() == hss.public_bytes()

    mt = allcrypt.XmssKey.from_seeds("XMSSMT-SHA2_20/4_256", bytes(32), bytes(32), bytes(32))
    key = allcrypt.HashSigPublicKey.from_public("XMSSMT", mt.public_bytes())
    assert key.scheme == "XMSS^MT" and key.parameter_set == "XMSSMT-SHA2_20/4_256"
    assert key.verify(b"m", mt.sign(b"m"))
    # The registries overlap: the same bytes - OID 2 - are an XMSS key
    # too, of another height, which does not verify XMSS^MT's signature.
    as_xmss = allcrypt.HashSigPublicKey.from_public("XMSS", mt.public_bytes())
    assert as_xmss.parameter_set == "XMSS-SHA2_16_256"
    assert not as_xmss.verify(b"m", mt.sign(b"m"))


def test_refusals():
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.HashSigPublicKey.from_public("SPHINCS", bytes(68))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.HashSigPublicKey.from_public("XMSS", bytes(68))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.HashSigPublicKey.from_public("HSS", bytes(60))
