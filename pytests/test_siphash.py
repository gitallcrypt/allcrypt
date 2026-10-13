"""SipHash and HalfSipHash against the designers' vectors
(`rfcs/siphash-vectors.h`) and `vectors/siphash.vec` (the designers'
reference, OpenSSL 3.5 and Bouncy Castle 1.77; written by
`scripts/make_siphash_vectors.py`)."""

import pathlib
import re

import pytest

import allcrypt

ROOT = pathlib.Path(__file__).resolve().parent.parent
DESIGNERS = (ROOT / "rfcs" / "siphash-vectors.h").read_text()
LINES = (ROOT / "vectors" / "siphash.vec").read_text().splitlines()


def fields(line):
    return dict(w.split("=", 1) for w in line.split()[1:])


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


MESSAGES = [unhex(fields(l)["data"]) for l in LINES if l.startswith("msg ")]
KEYS = [unhex(fields(l)["data"]) for l in LINES if l.startswith("key ")]


def table(name):
    body = DESIGNERS[DESIGNERS.index(name + "["):]
    body = body[body.index("{") + 1:body.index("};")]
    return [bytes(int(b, 16) for b in re.findall(r"0x([0-9a-f]{2})", row))
            for row in body.split("}") if "0x" in row]


@pytest.mark.parametrize("name,size,half", [("vectors_sip64", 8, False),
                                            ("vectors_sip128", 16, False),
                                            ("vectors_hsip32", 4, True),
                                            ("vectors_hsip64", 8, True)])
def test_the_designers_vectors(name, size, half):
    rows = table(name)
    assert len(rows) == 64
    key = bytes(range(16))
    for i, expected in enumerate(rows):
        if half:
            assert allcrypt.halfsiphash(key[:8], bytes(range(i)), size=size) == expected
        else:
            assert allcrypt.siphash(key, bytes(range(i)), size=size) == expected


def test_against_three_implementations():
    rows = [fields(l) for l in LINES if l.startswith("mac ")]
    assert len(rows) == 1472 and len(MESSAGES) == 46 and len(KEYS) == 2
    for row in rows:
        key = KEYS[int(row["key"])]
        function = allcrypt.siphash if row["kind"] == "siphash" else allcrypt.halfsiphash
        if row["kind"] == "halfsiphash":
            key = key[:8]
        got = function(key, MESSAGES[int(row["msg"])], c_rounds=int(row["c"]),
                       d_rounds=int(row["d"]), size=int(row["size"]))
        assert got.hex() == row["tag"]


def test_refusals():
    with pytest.raises(ValueError):
        allcrypt.siphash(bytes(8), b"")
    with pytest.raises(ValueError):
        allcrypt.halfsiphash(bytes(8), b"", size=16)
    with pytest.raises(ValueError):
        allcrypt.siphash(bytes(16), b"", c_rounds=0)
