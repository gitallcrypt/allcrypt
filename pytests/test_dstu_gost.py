"""Ukraine's GOST through the Python bindings: the DSTU 4145 default DKE
as a GOST parameter set, GOST 34.311-95 and the DSTU key wrap. The Rust
tests hold the breakage checks; this checks the binding against the
rows of vectors/dstu_gost.vec, which Bouncy Castle and gost89 wrote."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "dstu_gost.vec")
DSTU = "dstu4145-default-dke"


def rows(kind):
    found = []
    with open(VECTORS) as f:
        for line in f:
            words = line.split()
            if words and words[0] == kind:
                found.append({k: bytes.fromhex(v) for k, v in
                              (w.split("=", 1) for w in words[1:])})
    assert found, kind
    return found


def test_the_parameter_set_is_the_dke_unpacked():
    dke = rows("dke")[0]["value"]
    want = [[b >> 4 if i % 2 == 0 else b & 15 for b in dke[8 * r:8 * r + 8] for i in (0, 1)]
            for r in range(8)]
    assert [list(r) for r in allcrypt.gost_sbox(DSTU)] == want


def test_gost34311_is_in_the_catalogue():
    assert "gost34311" in allcrypt.algorithms_available
    # Lowercased, as hashlib names are.
    assert allcrypt.new("gost34311").name == "gost34311"


def test_gost34311_vectors():
    for r in rows("gost34311"):
        assert allcrypt.new("gost34311", r["msg"]).digest() == r["digest"]


@pytest.mark.parametrize("kind,mode", [("gost-ecb", "ecb"), ("gost-cfb", "cfb"),
                                       ("gost-cnt", "ctr")])
def test_cipher_modes(kind, mode):
    for r in rows(kind):
        cipher = allcrypt.Cipher("gost", r["key"], DSTU)
        if mode == "ecb":
            assert cipher.encrypt(mode, r["pt"]) == r["ct"]
        else:
            assert cipher.encrypt(mode, r["pt"], iv=r["iv"]) == r["ct"]
            assert cipher.decrypt(mode, r["ct"], iv=r["iv"]) == r["pt"]


def test_key_wrap_vectors():
    for r in rows("wrap"):
        assert allcrypt.dstu_gost_key_wrap(r["kek"], r["cek"], r["iv"]) == r["wrapped"]
        assert allcrypt.dstu_gost_key_unwrap(r["kek"], r["wrapped"]) == r["cek"]


def test_key_wrap_random_iv_and_refusals():
    kek, cek = bytes(range(32)), bytes(range(32, 64))
    wrapped = allcrypt.dstu_gost_key_wrap(kek, cek)
    assert len(wrapped) == 44
    assert allcrypt.dstu_gost_key_unwrap(kek, wrapped) == cek
    damaged = bytes([wrapped[0] ^ 1]) + wrapped[1:]
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.dstu_gost_key_unwrap(kek, damaged)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.dstu_gost_key_wrap(kek, cek[:16])
