"""MurmurHash3 against `vectors/murmur3.vec` (PHP, SMHasher's reference,
the murmur3 crate, murmurhash3js, spaolacci/murmur3 and twmb/murmur3;
written by `scripts/make_murmur3_vectors.py`)."""

import pathlib

import pytest

import allcrypt

LINES = (pathlib.Path(__file__).resolve().parent.parent / "vectors"
         / "murmur3.vec").read_text().splitlines()


def rows(kind):
    return [dict(w.split("=", 1) for w in line.split()[1:])
            for line in LINES if line.split()[0] == kind]


MESSAGES = [bytes.fromhex(f["fill"]) * int(f["len"]) if "fill" in f
            else b"" if f["data"] == "-" else bytes.fromhex(f["data"]) for f in rows("msg")]
FUNCTIONS = {"murmur3_32": allcrypt.murmur3_32, "murmur3_x86_128": allcrypt.murmur3_x86_128,
             "murmur3_x64_128": allcrypt.murmur3_x64_128}
PHP = {"murmur3_32": "murmur3a", "murmur3_x86_128": "murmur3c", "murmur3_x64_128": "murmur3f"}


def test_the_file():
    assert len(MESSAGES) == 50
    assert len(rows("hash")) == 900


@pytest.mark.parametrize("name", sorted(FUNCTIONS))
def test_each(name):
    for row in rows("hash"):
        if row["name"] != name:
            continue
        message, seed, value = MESSAGES[int(row["msg"])], int(row["seed"], 16), row["value"]
        assert FUNCTIONS[name](message, seed) == int(value, 16)
        h = allcrypt.Murmur3(name, message, seed=seed)
        assert (h.name, h.digest_size) == (name, len(value) // 2)
        assert h.hexdigest() == value
        assert h.digest() == bytes.fromhex(value)
        assert h.intdigest() == int(value, 16)
        pieces = allcrypt.Murmur3(PHP[name], seed=seed)
        for at in range(0, len(message), 7):
            pieces.update(memoryview(message)[at:at + 7])
            pieces.copy().hexdigest()
        assert pieces.hexdigest() == value
        if seed == 0:
            assert allcrypt.new(name, message).hexdigest() == value


def test_what_is_refused():
    with pytest.raises(ValueError, match="murmur3_x64_128"):
        allcrypt.Murmur3("murmur2")
    with pytest.raises(OverflowError):
        allcrypt.murmur3_32(b"", 1 << 32)
    with pytest.raises(OverflowError):
        allcrypt.Murmur3("murmur3_32", seed=-1)
