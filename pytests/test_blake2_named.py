"""The BLAKE2 output lengths the catalogue names, against
`vectors/blake2_named.vec` (hashlib, OpenSSL 3.5 and, for BLAKE2b,
b2sum; written by `scripts/make_blake2_vectors.py`)."""

import pathlib

import pytest

import allcrypt

ROWS = [dict(field.split("=", 1) for field in line.split()[1:])
        for line in (pathlib.Path(__file__).resolve().parent.parent / "vectors"
                     / "blake2_named.vec").read_text().splitlines()
        if line.startswith("hash ")]
NAMES = ["blake2b_128", "blake2b_160", "blake2b_256", "blake2b_384", "blake2s_128",
         "blake2s_160"]


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def test_the_names_are_in_the_catalogue():
    assert len(ROWS) == 102
    for name in NAMES:
        assert name in allcrypt.algorithms_available
        assert allcrypt.HashName(name) == name


@pytest.mark.parametrize("name", NAMES)
def test_each_named_length(name):
    rows = [r for r in ROWS if r["name"] == name]
    assert len(rows) == 17
    for row in rows:
        h = allcrypt.new(name, unhex(row["msg"]))
        assert h.name == name
        assert h.hexdigest() == row["digest"]
        assert allcrypt.new(name.upper().replace("_", "-"), unhex(row["msg"])).hexdigest() \
            == row["digest"]
