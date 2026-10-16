"""Jenkins's one-at-a-time against `vectors/joaat.vec` (PHP, Perl 5.24 and
gVisor; written by `scripts/make_joaat_vectors.py`)."""

import pathlib

import pytest

import allcrypt

LINES = (pathlib.Path(__file__).resolve().parent.parent / "vectors"
         / "joaat.vec").read_text().splitlines()


def rows(kind):
    return [dict(w.split("=", 1) for w in line.split()[1:])
            for line in LINES if line.split()[0] == kind]


MESSAGES = [bytes.fromhex(f["fill"]) * int(f["len"]) if "fill" in f
            else b"" if f["data"] == "-" else bytes.fromhex(f["data"]) for f in rows("msg")]


def test_every_row():
    assert len(MESSAGES) == 28
    assert len(rows("hash")) == 140
    for row in rows("hash"):
        message, seed, value = MESSAGES[int(row["msg"])], int(row["seed"], 16), row["value"]
        assert allcrypt.joaat(message, seed) == int(value, 16)
        third = len(message) // 3
        state = allcrypt.joaat_update(message[third:], allcrypt.joaat_update(message[:third], seed))
        assert allcrypt.joaat_finish(state) == int(value, 16)
        if seed == 0:
            h = allcrypt.new("joaat")
            for at in range(0, len(message), 5):
                h.update(memoryview(message)[at:at + 5])
            assert (h.name, h.hexdigest()) == ("joaat", value)
            assert allcrypt.new("one_at_a_time", message).hexdigest() == value


def test_what_is_refused():
    with pytest.raises(OverflowError):
        allcrypt.joaat(b"", 1 << 32)
    with pytest.raises(OverflowError):
        allcrypt.joaat_finish(-1)
