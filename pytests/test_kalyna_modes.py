"""DSTU 7624's modes over Kalyna through the Python bindings: its
counter mode as `ctr` on a Kalyna cipher, the MAC and the key wrap,
against vectors/kalyna_modes.vec (Bouncy Castle and cryptonite)."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "kalyna_modes.vec")


def rows(kind):
    found = []
    with open(VECTORS) as f:
        for line in f:
            words = line.split()
            if words and words[0] == kind:
                found.append({k: (b"" if v == "-" else bytes.fromhex(v)) if k not in ("mode", "source", "block", "q") else v
                              for k, v in (w.split("=", 1) for w in words[1:])})
    assert found, kind
    return found


def name(row):
    return f"kalyna-{8 * int(row['block'])}"


def test_streaming_modes():
    for r in rows("stream"):
        c = allcrypt.Cipher(name(r), r["key"])
        assert c.encrypt(r["mode"], r["pt"], iv=r["iv"]) == r["ct"], r
        assert c.decrypt(r["mode"], r["ct"], iv=r["iv"]) == r["pt"], r


def test_mac():
    for r in rows("mac"):
        assert allcrypt.kalyna_mac(name(r), r["key"], r["msg"], int(r["q"])) == r["tag"], r


def test_key_wrap():
    for r in rows("kw"):
        assert allcrypt.kalyna_key_wrap(name(r), r["key"], r["data"]) == r["wrapped"], r
        if len(r["data"]) % int(r["block"]) == 0:
            assert allcrypt.kalyna_key_unwrap(name(r), r["key"], r["wrapped"]) == r["data"]
        else:
            assert allcrypt.kalyna_key_unwrap_padded(name(r), r["key"], r["wrapped"]) == r["data"]


def test_refusals():
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.kalyna_mac("aes", bytes(16), b"x", 16)
    wrapped = allcrypt.kalyna_key_wrap("kalyna-128", bytes(16), bytes(32))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.kalyna_key_unwrap("kalyna-128", bytes([1]) + bytes(15), wrapped)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.kalyna_key_unwrap_padded("kalyna-128", bytes(16), wrapped)
