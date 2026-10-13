"""Tiger, Tiger2, HAVAL and Snefru against `vectors/tiger_haval_snefru.vec`
(PHP, sphlib, RHash, mhash and Botan 1.10.17; written by
`scripts/make_tiger_haval_snefru_vectors.py`)."""

import pathlib

import pytest

import allcrypt

LINES = (pathlib.Path(__file__).resolve().parent.parent / "vectors"
         / "tiger_haval_snefru.vec").read_text().splitlines()
MESSAGES = [b"" if f["data"] == "-" else bytes.fromhex(f["data"])
            for f in (dict(w.split("=", 1) for w in line.split()[1:])
                      for line in LINES if line.startswith("msg "))]
ROWS = [dict(w.split("=", 1) for w in line.split()[1:])
        for line in LINES if line.startswith("hash ")]
NAMES = sorted({r["name"] for r in ROWS})


def test_the_file():
    assert len(MESSAGES) == 30
    assert len(ROWS) == 780
    assert len(NAMES) == 26


@pytest.mark.parametrize("name", NAMES)
def test_each_name(name):
    rows = [r for r in ROWS if r["name"] == name]
    assert len(rows) == 30
    # tiger192_5 and tiger160_6 are reachable by name but not catalogued.
    assert (name in allcrypt.algorithms_available) == (name not in ("tiger192_5", "tiger160_6"))
    for row in rows:
        message = MESSAGES[int(row["msg"])]
        h = allcrypt.new(name, message)
        assert h.name == name
        assert h.digest_size == len(row["digest"]) // 2
        assert h.hexdigest() == row["digest"]
        pieces = allcrypt.new(name)
        for at in range(0, len(message), 7):
            pieces.update(memoryview(message)[at:at + 7])
        assert pieces.hexdigest() == row["digest"]


def test_php_spellings():
    row = next(r for r in ROWS if r["name"] == "haval224_4" and r["msg"] == "29")
    assert allcrypt.new("haval224,4", MESSAGES[29]).hexdigest() == row["digest"]
    row = next(r for r in ROWS if r["name"] == "tiger" and r["msg"] == "29")
    assert allcrypt.new("tiger192,3", MESSAGES[29]).hexdigest() == row["digest"]
    row = next(r for r in ROWS if r["name"] == "snefru256" and r["msg"] == "29")
    assert allcrypt.new("snefru", MESSAGES[29]).hexdigest() == row["digest"]


@pytest.mark.parametrize("name", ["tiger256_3", "tiger192_2", "haval256_6", "haval100_3"])
def test_what_is_not_one_is_refused(name):
    with pytest.raises(ValueError):
        allcrypt.new(name)
