"""ssdeep and CTPH through Python, against `vectors/ssdeep.vec`
(libfuzzy 2.14.1 and ppdeep's digests, libfuzzy's scores, ctph.js
0.0.5's digests and similarities; written by
`scripts/make_ssdeep_vectors.py`, whose rule builds the messages)."""

import hashlib
import math
import pathlib

import pytest

import allcrypt

LINES = (pathlib.Path(__file__).resolve().parent.parent / "vectors" / "ssdeep.vec") \
    .read_text().splitlines()


def rows(kind):
    return [dict(f.split("=", 1) for f in line.split()[1:]) for line in LINES
            if line.split(" ", 1)[0] == kind]


def random_bytes(seed, length):
    out, i = bytearray(), 0
    while len(out) < length:
        out += hashlib.sha256(b"allcrypt ssdeep" + seed.to_bytes(4, "big")
                              + i.to_bytes(4, "big")).digest()
        i += 1
    return bytes(out[:length])


def message(spec):
    kind, *f = spec.split(":")
    if kind == "random":
        return random_bytes(int(f[0]), int(f[1]))
    if kind == "zeros":
        return bytes(int(f[0]))
    if kind == "repeat":
        unit, length = bytes.fromhex(f[0]), int(f[1])
        return (unit * (length // len(unit) + 1))[:length]
    if kind == "counting":
        length, text, i = int(f[0]), bytearray(), 0
        while len(text) < length:
            text += f"{i}\n".encode()
            i += 1
        return bytes(text[:length])
    base = bytearray(random_bytes(int(f[0]), int(f[1])))
    if kind == "spliced":
        patch = bytes.fromhex(f[3])
        base[int(f[2]):int(f[2]) + len(patch)] = patch
        return bytes(base)
    at, n = int(f[2]), int(f[3])
    base[at:at + n] = random_bytes(int(f[4]), n)
    return bytes(base)


@pytest.mark.parametrize("row", rows("hash"), ids=lambda r: r["msg"][:40])
def test_digests(row):
    data = message(row["msg"])
    assert allcrypt.ssdeep(data) == row["ssdeep"]
    assert allcrypt.ctph(data) == row["ctph"]
    state = allcrypt.Ssdeep(data[:len(data) // 3])
    fork = state.copy()
    state.update(memoryview(data)[len(data) // 3:])
    assert state.digest() == row["ssdeep"]
    fork.update(data[len(data) // 3:])
    assert fork.digest() == row["ssdeep"]


def test_scores():
    found = rows("compare")
    assert len(found) == 184
    for row in found:
        if row["score"] == "error":
            with pytest.raises(allcrypt.CryptoError):
                allcrypt.ssdeep_compare(row["a"], row["b"])
        else:
            assert allcrypt.ssdeep_compare(row["a"], row["b"]) == int(row["score"])


def test_ctph_similarity():
    found = rows("similarity")
    assert len(found) == 175
    for row in found:
        if row["score"] == "error":
            with pytest.raises(allcrypt.CryptoError):
                allcrypt.ctph_similarity(row["a"], row["b"])
        elif row["score"] == "NaN":
            assert math.isnan(allcrypt.ctph_similarity(row["a"], row["b"]))
        else:
            assert allcrypt.ctph_similarity(row["a"], row["b"]) == float(row["score"])
