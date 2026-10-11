"""GOST R 34.11-94's two readings of the empty message through Python,
against the witnesses' answers in `vectors/gost94_readings.vec`: the
`_bc` names match every `gost94` row (Bouncy Castle's and gost89's
reading), and the plain names match every row with a message and
cryptonite's `gost94-zero` rows for the empty one."""

import pathlib

import allcrypt

LINES = [line for line in (pathlib.Path(__file__).resolve().parent.parent / "vectors"
                           / "gost94_readings.vec").read_text().splitlines()
         if line and not line.startswith("#")]
ROWS = [dict(field.split("=", 1) for field in line.split()[1:])
        for line in LINES if line.startswith("gost94 ")]
ZERO = [dict(field.split("=", 1) for field in line.split()[1:])
        for line in LINES if line.startswith("gost94-zero ")]
NAMES = {"id-GostR3411-94-CryptoProParamSet": "gost94",
         "id-GostR3411-94-TestParamSet": "gost94_test",
         "dstu4145-default-dke": "gost34311"}


def test_both_readings_against_the_witnesses():
    assert len(ROWS) == 27
    for row in ROWS:
        name = NAMES[row["params"]]
        message = b"" if row["msg"] == "-" else bytes.fromhex(row["msg"])
        expected = bytes.fromhex(row["digest"])
        assert allcrypt.new(name + "_bc", message).digest() == expected
        if message:
            assert allcrypt.new(name, message).digest() == expected
        else:
            assert allcrypt.new(name, message).digest() != expected


def test_the_plain_names_are_cryptonites_reading_of_the_empty_message():
    assert len(ZERO) == 3
    for row in ZERO:
        name = NAMES[row["params"]]
        assert allcrypt.new(name, b"").hexdigest() == row["digest"]
        assert allcrypt.new(name + "_bc", b"").hexdigest() != row["digest"]


def test_the_names_are_in_the_catalogue():
    for name in NAMES.values():
        assert name + "_bc" in allcrypt.algorithms_available
        assert allcrypt.new(name + "_bc").name == name + "_bc"
        assert allcrypt.new(name + "_bc").digest_size == 32
