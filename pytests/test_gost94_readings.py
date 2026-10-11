"""GOST R 34.11-94's two readings of the empty message through Python,
against Bouncy Castle's and gost89's answers in
`vectors/gost94_readings.vec`: the `_bc` names match every row, and the
plain names match every row but the empty message."""

import pathlib

import allcrypt

ROWS = [dict(field.split("=", 1) for field in line.split()[1:])
        for line in (pathlib.Path(__file__).resolve().parent.parent / "vectors"
                     / "gost94_readings.vec").read_text().splitlines()
        if line and not line.startswith("#")]
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


def test_the_names_are_in_the_catalogue():
    for name in NAMES.values():
        assert name + "_bc" in allcrypt.algorithms_available
        assert allcrypt.new(name + "_bc").name == name + "_bc"
        assert allcrypt.new(name + "_bc").digest_size == 32
