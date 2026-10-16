"""Rabbit, HC-128, HC-256 and SOSEMANUK through the Python binding. The
Rust test holds every row of vectors/estream.vec; this checks the
binding on all of them and the refusals."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "estream.vec")


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def test_estream_rows():
    count = 0
    with open(VECTORS) as f:
        for line in f:
            if not line.startswith("stream "):
                continue
            r = dict(w.split("=", 1) for w in line.split()[1:])
            want = unhex(r["keystream"])
            iv = unhex(r["iv"]) or None
            got = allcrypt.StreamCipher(r["cipher"], unhex(r["key"]), iv).encrypt(bytes(len(want)))
            assert got == want, line[:120]
            count += 1
    assert count >= 400


@pytest.mark.parametrize("name", ["rabbit", "hc128", "hc256", "sosemanuk"])
def test_the_names_are_listed(name):
    assert name in allcrypt.stream_ciphers_available
    assert allcrypt.StreamCipherName(name) == name


@pytest.mark.parametrize("name,key,iv", [
    ("rabbit", 15, 8), ("rabbit", 16, 4), ("hc128", 32, 16), ("hc128", 16, 12),
    ("hc256", 16, 32), ("hc256", 32, 16), ("sosemanuk", 33, 16), ("sosemanuk", 16, 8),
])
def test_wrong_lengths_are_refused(name, key, iv):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.StreamCipher(name, bytes(key), bytes(iv))
