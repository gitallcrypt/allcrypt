"""DSTU 7564's MAC over Kupyna through the Python binding. The Rust test
holds every row of vectors/kupyna_mac.vec; this checks the binding on
all of them and the refused sizes."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "kupyna_mac.vec")


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def test_kupyna_mac_rows():
    count = 0
    with open(VECTORS) as f:
        for line in f:
            if not line.startswith("kmac "):
                continue
            r = dict(w.split("=", 1) for w in line.split()[1:])
            assert allcrypt.kupyna_mac(int(r["bits"]), unhex(r["key"]),
                                       unhex(r["msg"])).hex() == r["mac"], line
            count += 1
    assert count >= 150


@pytest.mark.parametrize("bits", [0, 128, 248, 255, 264, 1024])
def test_other_sizes_are_refused(bits):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.kupyna_mac(bits, bytes(32), b"m")
