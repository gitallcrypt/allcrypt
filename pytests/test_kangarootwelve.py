"""TurboSHAKE and KangarooTwelve through the Python binding. The Rust test
holds RFC 9861's vectors and every row of vectors/turboshake_k12.vec; this
checks the binding on some of the rows, the catalogue names and the
refusals."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "turboshake_k12.vec")


def ptn(n):
    return bytes(i % 251 for i in range(n))


def test_witness_rows():
    seen = {}
    with open(VECTORS) as f:
        for line in f:
            if line.startswith("#"):
                continue
            kind, *fields = line.split()
            r = dict(w.split("=", 1) for w in fields)
            seen[kind] = seen.get(kind, 0) + 1
            if seen[kind] > 60:
                continue
            message, length = ptn(int(r["message_len"])), int(r["length"])
            if kind.startswith("turboshake"):
                got = allcrypt.turboshake(kind, message, length, domain=int(r["domain"], 16))
            else:
                got = allcrypt.kangarootwelve(kind, memoryview(message), length,
                                              customization=bytearray(ptn(int(r["custom_len"]))))
            assert got.hex() == r["output"], (kind, r)
    assert set(seen) == {"turboshake128", "turboshake256", "kt128", "kt256"}


def test_catalogue_names():
    data = ptn(9000)
    for name, xof, length in [("turboshake_128", "turboshake128", 32),
                              ("turboshake_256", "turboshake256", 64)]:
        assert allcrypt.new(name, data).digest() == allcrypt.turboshake(xof, data, length)
    for name, length in [("kt128", 32), ("kt256", 64)]:
        assert allcrypt.new(name, data).digest() == allcrypt.kangarootwelve(name, data, length)
    # A longer output extends a shorter one.
    assert allcrypt.kangarootwelve("kt128", data, 100)[:40] == allcrypt.kangarootwelve(
        "kt128", data, 40)


def test_refusals():
    with pytest.raises(ValueError, match="0x01 to 0x7F"):
        allcrypt.turboshake("turboshake128", b"", 32, domain=0x80)
    with pytest.raises(ValueError, match="TurboSHAKE"):
        allcrypt.turboshake("shake128", b"", 32)
    with pytest.raises(ValueError, match="KangarooTwelve"):
        allcrypt.kangarootwelve("kt512", b"", 32)
