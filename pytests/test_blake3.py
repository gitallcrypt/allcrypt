"""BLAKE3 against the BLAKE3 team's test vectors
(`rfcs/blake3-test-vectors.json`) and `vectors/blake3.vec` (their C and
reference implementations and Bouncy Castle; written by
`scripts/make_blake3_vectors.py`)."""

import hashlib
import json
import pathlib

import pytest

import allcrypt

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEAM = json.loads((ROOT / "rfcs" / "blake3-test-vectors.json").read_text())
LINES = (ROOT / "vectors" / "blake3.vec").read_text().splitlines()
KEY = bytes.fromhex(next(l for l in LINES if l.startswith("# KEY="))[6:])
CONTEXT = next(l for l in LINES if l.startswith("# CONTEXT="))[10:]


def fields(line):
    return dict(w.split("=", 1) for w in line.split()[1:])


def message(seed, length):
    out = b""
    j = 0
    while len(out) < length:
        out += hashlib.sha256(f"{seed}:{j}".encode()).digest()
        j += 1
    return out[:length]


MESSAGES = [message(f["seed"], int(f["len"]))
            for f in (fields(l) for l in LINES if l.startswith("msg "))]


def test_the_teams_vectors():
    assert len(TEAM["cases"]) == 35
    key = TEAM["key"].encode()
    for case in TEAM["cases"]:
        data = bytes(i % 251 for i in range(case["input_len"]))
        for expected, kwargs in [(case["hash"], {}), (case["keyed_hash"], {"key": key}),
                                 (case["derive_key"],
                                  {"derive_key_context": TEAM["context_string"]})]:
            assert allcrypt.blake3_xof(data, 131, **kwargs).hex() == expected
            assert allcrypt.blake3(data, **kwargs).hexdigest() == expected[:64]
            assert allcrypt.blake3_xof(data, 10, seek=100, **kwargs).hex() == expected[200:220]


@pytest.mark.parametrize("kind", ["out", "seek"])
def test_against_three_implementations(kind):
    assert len(MESSAGES) == 28
    rows = [fields(l) for l in LINES if l.startswith(kind + " ")]
    assert len(rows) == {"out": 504, "seek": 27}[kind]
    for row in rows:
        kwargs = {"hash": {}, "keyed": {"key": KEY},
                  "derive": {"derive_key_context": CONTEXT}}[row["mode"]]
        got = allcrypt.blake3_xof(MESSAGES[int(row["msg"])], int(row["length"]),
                                  seek=int(row["seek"]), **kwargs)
        assert got.hex() == row["digest"]


def test_the_hash_object():
    data = MESSAGES[10]
    h = allcrypt.blake3(key=KEY)
    for at in range(0, len(data), 100):
        h.update(memoryview(data)[at:at + 100])
    assert h.digest() == allcrypt.blake3_xof(data, 32, key=KEY)
    assert h.name == "blake3" and h.digest_size == 32
    assert allcrypt.new("blake3", data).digest() == allcrypt.blake3_xof(data, 32)
    assert "blake3" in allcrypt.algorithms_available


def test_refusals():
    with pytest.raises(ValueError):
        allcrypt.blake3(key=bytes(31))
    with pytest.raises(ValueError):
        allcrypt.blake3(key=bytes(32), derive_key_context="x")
    with pytest.raises(ValueError):
        allcrypt.blake3_xof(b"", 32, key=bytes(16))
