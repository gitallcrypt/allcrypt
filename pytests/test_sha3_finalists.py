"""The SHA-3 finalists as their teams finally submitted them, against
`vectors/sha3_finalists.vec` (written by `scripts/make_finalist_vectors.py`)."""

import pathlib

import pytest

import allcrypt

LINES = (pathlib.Path(__file__).resolve().parent.parent / "vectors"
         / "sha3_finalists.vec").read_text().splitlines()
MESSAGES = [b"" if f["data"] == "-" else bytes.fromhex(f["data"])
            for f in (dict(w.split("=", 1) for w in line.split()[1:])
                      for line in LINES if line.startswith("msg "))]
ROWS = [dict(w.split("=", 1) for w in line.split()[1:])
        for line in LINES if line.startswith("hash ")]
NAMES = ["blake224", "blake256", "blake384", "blake512",
         "groestl224", "groestl256", "groestl384", "groestl512",
         "jh224", "jh256", "jh384", "jh512",
         "skein256_128", "skein256_160", "skein256_224", "skein256_256",
         "skein512_128", "skein512_160", "skein512_224", "skein512_256", "skein512_384",
         "skein512_512", "skein1024_384", "skein1024_512", "skein1024_1024"]
# Reachable by name, not catalogued.
MORE = ["skein256_8", "skein512_1032", "skein1024_2056"]


def test_the_file():
    assert len(MESSAGES) == 34
    assert len(ROWS) == 952
    assert sorted({r["name"] for r in ROWS}) == sorted(NAMES + MORE)


@pytest.mark.parametrize("name", NAMES + MORE)
def test_each_name(name):
    assert (name in allcrypt.algorithms_available) == (name in NAMES)
    rows = [r for r in ROWS if r["name"] == name]
    assert len(rows) == 34
    for row in rows:
        message = MESSAGES[int(row["msg"])]
        h = allcrypt.new(name, message)
        assert h.name == name
        assert h.digest_size == len(row["digest"]) // 2
        assert h.hexdigest() == row["digest"]
        pieces = allcrypt.new(name)
        for at in range(0, len(message), 13):
            pieces.update(bytearray(message[at:at + 13]))
        assert pieces.hexdigest() == row["digest"]
