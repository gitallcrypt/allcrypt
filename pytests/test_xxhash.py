"""xxHash against `vectors/xxhash.vec` (PHP, the reference C, twox-hash,
OneOfOne/xxhash, cespare/xxhash, pierrec/xxHash and zeebo/xxh3; written
by `scripts/make_xxhash_vectors.py`)."""

import pathlib

import pytest

import allcrypt

LINES = (pathlib.Path(__file__).resolve().parent.parent / "vectors"
         / "xxhash.vec").read_text().splitlines()


def rows(kind):
    return [dict(w.split("=", 1) for w in line.split()[1:])
            for line in LINES if line.split()[0] == kind]


MESSAGES = [bytes.fromhex(f["fill"]) * int(f["len"]) if "fill" in f
            else b"" if f["data"] == "-" else bytes.fromhex(f["data"]) for f in rows("msg")]
SECRETS = {f["n"]: bytes.fromhex(f["data"]) for f in rows("secret")}
FUNCTIONS = {"xxh32": allcrypt.xxh32, "xxh64": allcrypt.xxh64, "xxh3": allcrypt.xxh3_64,
             "xxh128": allcrypt.xxh3_128}


def test_the_file():
    assert len(MESSAGES) == 59
    assert len(SECRETS) == 7
    assert len(rows("seeded")) == 25 * 59
    assert len(rows("keyed")) == 12 * 59


@pytest.mark.parametrize("name", ["xxh32", "xxh64", "xxh3", "xxh128"])
def test_seeded(name):
    for row in rows("seeded"):
        if row["name"] != name:
            continue
        message, seed, value = MESSAGES[int(row["msg"])], int(row["seed"], 16), row["value"]
        assert FUNCTIONS[name](message, seed) == int(value, 16)
        h = allcrypt.XxHash(name, message, seed=seed)
        assert (h.name, h.digest_size) == (name, len(value) // 2)
        assert h.hexdigest() == value
        assert h.digest() == bytes.fromhex(value)
        assert h.intdigest() == int(value, 16)
        pieces = allcrypt.XxHash(name, seed=seed)
        for at in range(0, len(message), 333):
            pieces.update(memoryview(message)[at:at + 333])
            pieces.copy().hexdigest()
        assert pieces.hexdigest() == value
        if seed == 0:
            assert allcrypt.new(name, message).hexdigest() == value


@pytest.mark.parametrize("name", ["xxh3", "xxh128"])
def test_with_a_secret(name):
    for row in rows("keyed"):
        if row["name"] != name:
            continue
        message, secret, value = MESSAGES[int(row["msg"])], SECRETS[row["secret"]], row["value"]
        assert FUNCTIONS[name](message, secret=secret) == int(value, 16)
        assert allcrypt.XxHash(name, message, secret=secret).hexdigest() == value


def test_what_is_refused():
    with pytest.raises(ValueError, match="136"):
        allcrypt.xxh3_64(b"", secret=SECRETS["short"])
    with pytest.raises(ValueError, match="not both"):
        allcrypt.xxh3_128(b"", seed=1, secret=SECRETS["0"])
    with pytest.raises(ValueError, match="Only XXH3"):
        allcrypt.XxHash("xxh64", secret=SECRETS["0"])
    with pytest.raises(ValueError, match="32 bits"):
        allcrypt.XxHash("xxh32", seed=1 << 32)
    with pytest.raises(OverflowError):
        allcrypt.xxh32(b"", 1 << 32)
    with pytest.raises(ValueError, match="xxh128"):
        allcrypt.XxHash("xxh16")
