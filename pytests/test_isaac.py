"""ISAAC, ISAAC-64 and Bouncy Castle's reading of ISAAC through the Python
bindings. The Rust tests hold every row of vectors/isaac.vec; this checks
the binding: the names, the rows without a skip and one with, uneven
pieces, and the refusals."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "isaac.vec")
NAMES = ("isaac", "isaac64", "isaac-bouncycastle")


def rows():
    with open(VECTORS) as f:
        for line in f:
            if line.split(" ", 1)[0] in NAMES:
                fields = dict(w.split("=", 1) for w in line.split()[1:])
                fields["cipher"] = line.split(" ", 1)[0]
                fields["key"] = b"" if fields["key"] == "-" else bytes.fromhex(fields["key"])
                yield fields


def test_isaac_is_in_the_catalogue():
    for name in NAMES:
        assert name in allcrypt.stream_ciphers_available


def test_isaac_vectors_through_stream_cipher():
    count = 0
    for r in rows():
        c = allcrypt.StreamCipher(r["cipher"], r["key"])
        c.encrypt(bytes(int(r["skip"])))
        assert c.encrypt(bytes(len(r["stream"]) // 2)).hex() == r["stream"], r["cipher"]
        count += 1
    assert count == 98


def test_isaac_in_pieces():
    r = next(r for r in rows() if r["source"] == "random" and len(r["key"]) == 100
             and r["cipher"] == "isaac64")
    c = allcrypt.StreamCipher("isaac64", r["key"])
    got = b"".join(c.encrypt(bytes(n)) for n in (1, 2, 2045, 4, 2044))
    assert got.hex() == r["stream"]


@pytest.mark.parametrize("name,maximum", [("isaac", 1024), ("isaac64", 2048),
                                          ("isaac-bouncycastle", 1024)])
def test_isaac_refusals(name, maximum):
    allcrypt.StreamCipher(name, bytes(maximum))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.StreamCipher(name, bytes(maximum + 1))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.StreamCipher(name, bytes(16), bytes(8))
