"""The named LCGs through the Python surface, against vectors/lcg.vec:
outputs recorded from libstdc++, musl, newlib, Wine's msvcrt, PCG, glibc
and the JDK by scripts/make_lcg_vectors.py. Offline."""

import os
import struct

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "lcg.vec")


def rows(kind):
    out = []
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                fields = dict(w.split("=", 1) for w in line.split()[1:])
                out.append(fields)
    assert len(out) > 10, kind
    return out


@pytest.mark.parametrize("row", rows("lcg"), ids=lambda r: f"{r['name']}-{r['seed']}-{r['skip']}")
def test_named_generators(row):
    g = allcrypt.Lcg(row["name"], int(row["seed"]))
    g.outputs(int(row["skip"]))
    assert g.outputs(len(row["outputs"].split(","))) == [int(v) for v in row["outputs"].split(",")]


def test_every_name_has_vectors_except_randu():
    names = {r["name"] for r in rows("lcg")}
    assert names == set(allcrypt.lcg_names()) - {"randu"}


def test_java_methods():
    calls = {
        "nextInt": lambda r, a: str(r.next_int()),
        "nextIntBounded": lambda r, a: str(r.next_int(a)),
        "nextLong": lambda r, a: str(r.next_long()),
        "nextBoolean": lambda r, a: str(r.next_boolean()).lower(),
        "nextFloat": lambda r, a: r.next_float(),
        "nextDouble": lambda r, a: r.next_double(),
        "nextBytes": lambda r, a: r.next_bytes(a).hex() or "-",
    }
    for row in rows("java"):
        r = allcrypt.JavaRandom(int(row["seed"]))
        arg = int(row["arg"])
        for want in row["outputs"].split(","):
            got = calls[row["method"]](r, arg)
            if row["method"] == "nextFloat":
                # Java printed the shortest decimal for a float, which
                # names the float only once rounded to single precision.
                assert got == struct.unpack("<f", struct.pack("<f", float(want)))[0], row
            elif isinstance(got, float):
                assert got == float(want), row
            else:
                assert got == want, row


def test_rand48_family():
    for row in rows("rand48"):
        r = allcrypt.Rand48()
        for step in row["setup"].split(";"):
            how, _, arg = step.partition(":")
            if how == "srand48":
                r.srand48(int(arg))
            elif how == "seed48":
                r.seed48([int(w) for w in arg.split(",")])
            elif how == "lcong48":
                r.lcong48([int(w) for w in arg.split(",")])
        for call, want in zip(row["calls"], row["outputs"].split(",")):
            got = {"l": r.lrand48, "m": r.mrand48, "d": r.drand48}[call]()
            assert got == (float(want) if call == "d" else int(want)), row


def test_randu_lies_on_its_planes():
    g = allcrypt.Lcg("randu", 1)
    x = [1] + g.outputs(1000)
    assert all(x[k + 2] == (6 * x[k + 1] - 9 * x[k]) % 2**31 for k in range(len(x) - 2))


def test_custom_parameters_and_their_refusals():
    g = allcrypt.Lcg.custom(1103515245, 12345, 2**31, 42)
    assert g.outputs(5) == allcrypt.Lcg("glibc_type0", 42).outputs(5)
    with pytest.raises(ValueError):
        allcrypt.Lcg.custom(1, 1, 1, 0)
    with pytest.raises(ValueError):
        allcrypt.Lcg.custom(1, 1, 7, 0, mask=0)
    with pytest.raises(ValueError, match="minstd_rand0"):
        allcrypt.Lcg("rand", 1)
    with pytest.raises(ValueError):
        allcrypt.JavaRandom(0).next_int(0)


def test_bytes_and_state():
    g = allcrypt.Lcg("msvc", 1)
    h = allcrypt.Lcg("msvc", 1)
    assert g.get_bytes(8) == bytes(v & 0xFF for v in h.outputs(8))
    g.seed(1)
    assert g.step() == 214013 + 2531011
    assert g.state == 214013 + 2531011
