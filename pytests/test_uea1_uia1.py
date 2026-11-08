"""UEA1 and UIA1 through the Python bindings. The Rust tests hold every row
of vectors/uea1_uia1.vec and Intel's tests; this checks the binding: the
names, every row through mobile_cipher and uia1, the default length, and
the refusals."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "uea1_uia1.vec")


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def test_the_names():
    assert "uea1" in allcrypt.mobile_ciphers_available
    assert callable(allcrypt.uia1)


def test_uea1_rows():
    count = 0
    for r in rows("uea1"):
        out = allcrypt.mobile_cipher("uea1", unhex(r["key"]), int(r["count"], 16),
                                     int(r["bearer"]), int(r["dir"]), unhex(r["data"]),
                                     int(r["bits"]))
        assert out == unhex(r["out"]), r["bits"]
        count += 1
    assert count == 105


def test_uia1_rows():
    count = 0
    for r in rows("uia1"):
        mac = allcrypt.uia1(unhex(r["key"]), int(r["count"], 16), int(r["fresh"], 16),
                            int(r["dir"]), unhex(r["data"]), int(r["bits"]))
        assert mac == unhex(r["out"]), r["bits"]
        count += 1
    assert count == 105


def test_the_whole_message_is_the_default():
    key, data = bytes(range(16)), bytes(range(40))
    assert allcrypt.uia1(key, 1, 2, 0, data) == allcrypt.uia1(key, 1, 2, 0, data, 320)


@pytest.mark.parametrize("call", [
    lambda: allcrypt.mobile_cipher("uea1", bytes(15), 0, 0, 0, b"x"),
    lambda: allcrypt.mobile_cipher("uea1", bytes(16), 0, 32, 0, b"x"),
    lambda: allcrypt.uia1(bytes(16), 0, 0, 2, b"x"),
    lambda: allcrypt.uia1(bytes(16), 0, 0, 0, b"xy", 17),
])
def test_refusals(call):
    with pytest.raises(allcrypt.CryptoError):
        call()
