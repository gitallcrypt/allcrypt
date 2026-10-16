"""PMAC through the Python binding. The Rust test holds every row of
vectors/pmac.vec; this checks the binding on all of them and the
refused block sizes."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "pmac.vec")


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def test_pmac_rows():
    count = 0
    with open(VECTORS) as f:
        for line in f:
            if not line.startswith("pmac "):
                continue
            r = dict(w.split("=", 1) for w in line.split()[1:])
            tag = allcrypt.pmac(r["cipher"], unhex(r["key"]), unhex(r["msg"]))
            assert tag.hex() == r["tag"], line
            count += 1
    assert count >= 70


@pytest.mark.parametrize("cipher,key_len", [("shacal2", 16), ("rijndael-256", 32),
                                            ("threefish512", 64)])
def test_other_block_sizes_are_refused(cipher, key_len):
    with pytest.raises(allcrypt.CryptoError, match="64 and 128 bit"):
        allcrypt.pmac(cipher, bytes(key_len), b"m")


def test_a_wrong_key_length_is_refused():
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.pmac("aes", bytes(15), b"m")
