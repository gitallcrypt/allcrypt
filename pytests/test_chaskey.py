"""Chaskey through the Python binding. The Rust test holds every row of
vectors/chaskey.vec; this checks the binding on all of them and the
refusals."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "chaskey.vec")


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def test_chaskey_rows():
    count = 0
    with open(VECTORS) as f:
        for line in f:
            if not line.startswith("chaskey "):
                continue
            r = dict(w.split("=", 1) for w in line.split()[1:])
            tag = allcrypt.chaskey(unhex(r["key"]), unhex(r["msg"]), rounds=int(r["rounds"]))
            assert tag.hex() == r["tag"], line
            count += 1
    assert count >= 190


def test_the_round_count_must_be_named():
    with pytest.raises(TypeError):
        allcrypt.chaskey(bytes(16), b"m")


@pytest.mark.parametrize("rounds", [0, 7, 9, 20])
def test_other_round_counts_are_refused(rounds):
    with pytest.raises(allcrypt.CryptoError, match=f"not {rounds}"):
        allcrypt.chaskey(bytes(16), b"m", rounds=rounds)


@pytest.mark.parametrize("length", [0, 15, 17, 32])
def test_other_key_lengths_are_refused(length):
    with pytest.raises(allcrypt.CryptoError, match="16 bytes"):
        allcrypt.chaskey(bytes(length), b"m", rounds=8)
