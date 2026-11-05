"""Trivium, Grain v1 and Grain-128 through the Python binding. The Rust
test holds the eSTREAM vectors and every row of vectors/trivium_grain.vec;
this checks the binding on the rows and the refusals."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "trivium_grain.vec")


def test_witness_rows():
    count = 0
    with open(VECTORS) as f:
        for line in f:
            if not line.startswith("stream "):
                continue
            r = dict(w.split("=", 1) for w in line.split()[1:])
            want = bytes.fromhex(r["keystream"])
            got = allcrypt.StreamCipher(r["cipher"], bytes.fromhex(r["key"]),
                                        bytes.fromhex(r["iv"])).encrypt(bytes(len(want)))
            assert got == want, line[:120]
            count += 1
    assert count >= 80


@pytest.mark.parametrize("name", ["trivium", "grainv1", "grain128"])
def test_the_names_are_listed(name):
    assert name in allcrypt.stream_ciphers_available
    assert allcrypt.StreamCipherName(name) == name


@pytest.mark.parametrize("name,key,iv", [
    ("trivium", 16, 10), ("trivium", 10, 12), ("trivium", 10, 5), ("trivium", 10, None),
    ("grainv1", 16, 8), ("grainv1", 10, 10), ("grain128", 10, 12), ("grain128", 16, 16),
])
def test_wrong_lengths_are_refused(name, key, iv):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.StreamCipher(name, bytes(key), None if iv is None else bytes(iv))
