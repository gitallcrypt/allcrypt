"""LMS and HSS through the Python bindings, against vectors/lms.vec
(written by scripts/make_lms_vectors.py; hash-sigs, Bouncy Castle 1.77 and
pyhsslms signing, those and hbs-lms verifying). Every signature in the file
is made again here from its seeds, which the Rust tests do only for the
trees that are cheap in a debug build."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "lms.vec")


def rows(kind):
    out = []
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                fields = dict(w.split("=", 1) for w in line.split()[1:])
                out.append({k: (b"" if v == "-" else bytes.fromhex(v))
                            if k in ("seed", "i", "msg", "public", "sig") else v
                            for k, v in fields.items()})
    return out


def test_the_file():
    assert (len(rows("lms")), len(rows("hss")), len(rows("bad"))) == (88, 37, 162)
    assert len(allcrypt.lms_parameter_sets()) == 20
    assert len(allcrypt.lmots_parameter_sets()) == 16
    assert {r["ots"] for r in rows("lms")} == set(allcrypt.lmots_parameter_sets())


def test_every_tree_is_signed_again():
    for row in rows("lms"):
        key = allcrypt.HssKey.from_seed([(row["lms"], row["ots"])], row["seed"], row["i"],
                                        int(row["q"]))
        assert key.public_bytes() == b"\x00\x00\x00\x01" + row["public"]
        assert key.sign(row["msg"]) == bytes(4) + row["sig"], (row["lms"], row["ots"])
        assert allcrypt.lms_verify(row["public"], row["msg"], row["sig"])
        assert not allcrypt.lms_verify(row["public"], row["msg"] + b"x", row["sig"])


def test_every_hierarchy_is_signed_again():
    for row in rows("hss"):
        levels = [tuple(pair.split("/")) for pair in row["levels"].split(",")]
        key = allcrypt.HssKey.from_seed(levels, row["seed"], row["i"], int(row["count"]))
        assert key.levels == levels
        assert key.public_bytes() == row["public"]
        assert key.sign(row["msg"]) == row["sig"], (row["levels"], row["count"])
        assert key.count == int(row["count"]) + 1
        assert allcrypt.hss_verify(row["public"], row["msg"], row["sig"])


def test_every_changed_signature_is_refused():
    for row in rows("bad"):
        assert not allcrypt.hss_verify(row["public"], row["msg"], row["sig"]), row["what"]


def test_the_key_moves_on_and_reads_back():
    levels = [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4")] * 2
    key = allcrypt.HssKey.from_seed(levels, bytes(range(24)), bytes(16))
    public = key.public_bytes()
    first = key.sign(b"one")
    saved = key.to_bytes()
    second = key.sign(b"two")
    assert first != second and key.count == 2 and key.remaining == 1024 - 2
    restored = allcrypt.HssKey.from_bytes(saved)
    assert restored.count == 1
    assert restored.sign(b"two") == second
    for message, sig in ((b"one", first), (b"two", second)):
        assert allcrypt.hss_verify(public, message, sig)
    assert not allcrypt.hss_verify(public, b"two", first)


def test_a_spent_key_refuses():
    key = allcrypt.HssKey.from_seed([("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W8")],
                                    bytes(24), bytes(16), 31)
    key.sign(b"the last leaf")
    assert key.remaining == 0
    with pytest.raises(ValueError, match="every signature"):
        key.sign(b"one more")


def test_generate_draws_fresh_seeds():
    a = allcrypt.HssKey.generate([("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W8")])
    b = allcrypt.HssKey.generate([("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W8")])
    assert a.public_bytes() != b.public_bytes()
    sig = a.sign(b"m")
    assert allcrypt.hss_verify(a.public_bytes(), b"m", sig)
    assert not allcrypt.hss_verify(b.public_bytes(), b"m", sig)


@pytest.mark.parametrize("levels, seed, i", [
    ([], bytes(32), bytes(16)),
    ([("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8")] * 9, bytes(32), bytes(16)),
    ([("LMS_SHA256_M32_H5", "LMOTS_SHA256_N24_W8")], bytes(32), bytes(16)),
    ([("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8")], bytes(24), bytes(16)),
    ([("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8")], bytes(32), bytes(15)),
    ([("LMS_SHA256_M32_H6", "LMOTS_SHA256_N32_W8")], bytes(32), bytes(16)),
])
def test_bad_parameters_are_refused(levels, seed, i):
    with pytest.raises(ValueError):
        allcrypt.HssKey.from_seed(levels, seed, i)
