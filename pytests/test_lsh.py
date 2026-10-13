"""LSH (KS X 3262) against `vectors/lsh.vec` (KISA's reference, Crypto++
and go-krypto; written by `scripts/make_lsh_vectors.py`)."""

import pathlib

import pytest

import allcrypt

LINES = (pathlib.Path(__file__).resolve().parent.parent / "vectors"
         / "lsh.vec").read_text().splitlines()
MESSAGES = [b"" if f["data"] == "-" else bytes.fromhex(f["data"])
            for f in (dict(w.split("=", 1) for w in line.split()[1:])
                      for line in LINES if line.startswith("msg "))]
ROWS = [dict(w.split("=", 1) for w in line.split()[1:])
        for line in LINES if line.startswith("hash ")]
NAMES = sorted({r["name"] for r in ROWS})
NAMED = {"lsh256_224", "lsh256_256", "lsh512_224", "lsh512_256", "lsh512_384", "lsh512_512"}


def test_the_file():
    assert len(MESSAGES) == 23
    assert len(ROWS) == 253
    assert len(NAMES) == 11


@pytest.mark.parametrize("name", NAMES)
def test_each_name(name):
    rows = [r for r in ROWS if r["name"] == name]
    assert len(rows) == 23
    assert (name in allcrypt.algorithms_available) == (name in NAMED)
    for row in rows:
        message = MESSAGES[int(row["msg"])]
        h = allcrypt.new(name, message)
        assert h.name == name
        assert h.digest_size == len(row["digest"]) // 2
        assert h.block_size == (128 if name.startswith("lsh256") else 256)
        assert h.hexdigest() == row["digest"]
        pieces = allcrypt.new(name)
        for at in range(0, len(message), 7):
            pieces.update(memoryview(message)[at:at + 7])
        assert pieces.hexdigest() == row["digest"]


def test_the_standards_spelling():
    row = next(r for r in ROWS if r["name"] == "lsh512_224" and r["msg"] == "22")
    h = allcrypt.new("LSH-512-224", MESSAGES[22])
    assert h.name == "lsh512_224"
    assert h.hexdigest() == row["digest"]


@pytest.mark.parametrize("name", ["lsh256_264", "lsh512_0", "lsh384_256", "lsh256_12",
                                  "lsh512"])
def test_what_is_not_one_is_refused(name):
    with pytest.raises(ValueError):
        allcrypt.new(name)
