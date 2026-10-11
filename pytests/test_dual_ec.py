"""Dual_EC_DRBG through the bindings, against vectors/dual_ec.vec: OpenSSL
FIPS module 2.0.5's answers, which Bouncy Castle 1.78.1 agrees with, and
six rows under another Q set in OpenSSL's code the way ScreenOS set its
own. scripts/make_dual_ec_vectors.py writes the file."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "vectors", "dual_ec.vec")


def rows():
    out = []
    for line in open(VECTORS):
        if line.startswith("#") or not line.strip():
            continue
        words = line.split()
        assert words[0] == "vector"
        fields = dict(word.split("=", 1) for word in words[1:])
        out.append({k: (b"" if v == "-" else bytes.fromhex(v))
                    if k not in ("curve", "hash", "source") else v
                    for k, v in fields.items()})
    assert len(out) >= 40
    return out


ROWS = rows()


def test_the_streaming_generator_is_openssls():
    under_q = 0
    for row in ROWS:
        drbg = allcrypt.DualEcDrbg(row["curve"], row["hash"], row["entropy"], row["nonce"],
                                   row["pers"], q=row.get("q"))
        assert drbg.generate(len(row["out1"]), row["adin1"]) == row["out1"]
        if row.get("reseed_entropy"):
            drbg.reseed(row["reseed_entropy"], row["reseed_adin"])
        assert drbg.generate(len(row["out2"]), row["adin2"]) == row["out2"]
        if "q" in row:
            assert drbg.q == row["q"]
            under_q += 1
    assert under_q == 6


def test_the_one_shot_and_the_generator_agree():
    for row in ROWS:
        if "q" in row or row.get("reseed_entropy"):
            continue
        one_shot = allcrypt.dual_ec_drbg(row["curve"], row["hash"], row["entropy"],
                                         row["nonce"], row["pers"],
                                         [(len(row["out1"]), row["adin1"]),
                                          (len(row["out2"]), row["adin2"])])
        assert one_shot == [row["out1"], row["out2"]]


def test_q_must_be_a_point_of_the_curve():
    row = ROWS[0]
    g = allcrypt.ec_generator("P-256")
    assert allcrypt.DualEcDrbg("P-256", "SHA-256", row["entropy"], row["nonce"], q=g).q == g
    for bad in (b"\x00", g[:-1] + bytes([g[-1] ^ 1]), allcrypt.ec_generator("P-384")):
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.DualEcDrbg("P-256", "SHA-256", row["entropy"], row["nonce"], q=bad)
