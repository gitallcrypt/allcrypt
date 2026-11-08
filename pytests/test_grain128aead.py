"""Grain-128AEADv2 and v1 through the Python bindings. The Rust tests hold
every row of vectors/grain128aead.vec and vectors/grain128aead_v1.vec;
this checks the binding: the names, every row sealed and opened through
`Aead`, a forged tag, and the refusals."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "grain128aead.vec")
VECTORS_V1 = os.path.join(os.path.dirname(__file__), "..", "vectors", "grain128aead_v1.vec")


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def rows(path=VECTORS, kind="grain128aeadv2"):
    with open(path) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield {k: (v if k in ("source", "witnesses") else unhex(v))
                       for k, v in (w.split("=", 1) for w in line.split()[1:])}


def test_grain128aead_is_in_the_catalogue():
    assert "grain128aeadv2" in allcrypt.aeads_available
    assert "grain128aeadv1" in allcrypt.aeads_available
    assert "grain128aead" not in allcrypt.aeads_available


@pytest.mark.parametrize("path,kind", [(VECTORS, "grain128aeadv2"),
                                       (VECTORS_V1, "grain128aeadv1")])
def test_grain128aead_vectors_through_aead(path, kind):
    count = 0
    for r in rows(path, kind):
        aead = allcrypt.Aead(r["key"], kind)
        sealed = aead.encrypt(r["nonce"], r["pt"], r["ad"])
        assert sealed == r["ct"] + r["tag"]
        assert aead.decrypt(r["nonce"], sealed, r["ad"]) == r["pt"]
        count += 1
    assert count == 1247


def test_the_bare_name_is_refused_and_names_both():
    with pytest.raises(allcrypt.CryptoError, match="grain128aeadv1.*grain128aeadv2"):
        allcrypt.Aead(bytes(16), "grain128aead").encrypt(bytes(12), b"x", b"")


def test_grain128aead_refuses_a_forged_tag():
    r = next(r for r in rows() if r["source"] == "random" and len(r["pt"]) == 17)
    aead = allcrypt.Aead(r["key"], "grain128aeadv2")
    forged = r["ct"] + bytes([r["tag"][0] ^ 1]) + r["tag"][1:]
    with pytest.raises(allcrypt.CryptoError):
        aead.decrypt(r["nonce"], forged, r["ad"])


@pytest.mark.parametrize("key,nonce", [(bytes(15), bytes(12)), (bytes(16), bytes(16))])
def test_grain128aead_refuses_lengths(key, nonce):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key, "grain128aeadv2").encrypt(nonce, b"x", b"")
