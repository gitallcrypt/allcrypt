"""XMSS and XMSS^MT through the Python bindings, against the reference
implementation's answers in Botan's tests (vectors/botan_xmss/) and
vectors/xmss.vec (written by scripts/make_xmss_vectors.py; the reference
implementation and Botan signing, Bouncy Castle verifying). Every key and
signature of the file is made again here from its seeds, which the Rust
tests do only for trees of height five. Each XMSS set's row uses the
reference's own keygen seeds, so one tree checks the reference's public
key and the file's signature together. The rows that would build a
second tree of height 10 for a set already covered are marked slow
(pytests/conftest.py)."""

import os

import pytest

import allcrypt

HERE = os.path.dirname(__file__)
VECTORS = os.path.join(HERE, "..", "vectors", "xmss.vec")
BOTAN = os.path.join(HERE, "..", "vectors", "botan_xmss")


def rows(kind):
    out = []
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                fields = dict(w.split("=", 1) for w in line.split()[1:])
                out.append({k: (b"" if v == "-" else bytes.fromhex(v))
                            if k in ("sk_seed", "sk_prf", "seed", "msg", "public", "sig") else v
                            for k, v in fields.items()})
    return out


def botan(name):
    out = []
    for line in open(os.path.join(BOTAN, name)):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key == "Params":
            out.append({})
        out[-1][key] = value
    return out


def full(name):
    return name if name.startswith("XMSS-") else "XMSS-" + name


def test_the_files():
    assert (len(rows("sign")), len(rows("rfc8391")), len(rows("bad"))) == (38, 5, 54)
    assert len(allcrypt.xmss_parameter_sets()) == 77


def test_the_reference_implementation_s_signatures_verify():
    # xmss_sig.vec: every signature under the public key at the front of
    # its private key, Botan's raw form - Botan 2's derivation among them.
    # Making them again would build 21 more trees of height 10; the
    # file's own rows, made from the reference's keygen seeds below,
    # already make the reference's signatures again.
    for r in botan("xmss_sig.vec"):
        name = full(r["Params"])
        n = {"256": 32, "512": 64, "192": 24}[name.rsplit("_", 1)[1]]
        public = bytes.fromhex(r["PrivateKey"])[:4 + 2 * n]
        assert allcrypt.xmss_verify(public, bytes.fromhex(r["Msg"]),
                                    bytes.fromhex(r["Signature"])), name


# A second tree of height 10 under a set the cheap test has already built
# one for: the first and last leaves of XMSS-SHA2_10_256, and XMSS^MT with
# two layers of height 10 across the end of its lowest tree.
def _is_slow(row):
    return (row["set"] == "XMSS-SHA2_10_256" and row["idx"] in ("0", "1023")) \
        or row["set"] == "XMSSMT-SHA2_20/2_256"


def _sign_again(selected):
    keys = {}
    for row in selected:
        mt = row["kind"] == "xmssmt"
        seeds = (row["set"], row["sk_seed"], row["sk_prf"], row["seed"])
        idx = int(row["idx"])
        key = keys.get(seeds)
        if key is None or key.index != idx:
            key = allcrypt.XmssKey.from_seeds(*seeds, idx)
        assert key.public_bytes() == row["public"]
        assert key.multi_tree == mt
        assert key.sign(row["msg"]) == row["sig"], (row["set"], idx)
        keys[seeds] = key
        check = allcrypt.xmssmt_verify if mt else allcrypt.xmss_verify
        assert check(row["public"], row["msg"], row["sig"])


def test_every_row_is_signed_again():
    # Every XMSS set once, each from the reference's keygen seeds
    # (xmss_keygen_reference.vec), so the one tree is checked against the
    # reference's public key as well as the file's signature; and every
    # XMSS^MT row with trees of height five or less.
    selected = [row for row in rows("sign") if not _is_slow(row)]
    reference = {r["Params"]: r for r in botan("xmss_keygen_reference.vec")}
    matched = set()
    for row in selected:
        r = reference.get(row["set"])
        if r is not None:
            assert (row["sk_seed"].hex(), row["sk_prf"].hex(), row["seed"].hex()) \
                == (r["SecretSeed"], r["SecretPrf"], r["PublicSeed"]), row["set"]
            assert row["public"].hex() == r["PublicKey"], row["set"]
            matched.add(row["set"])
    assert matched == set(reference)
    assert len(selected) == 7 + 24 + 3
    _sign_again(selected)


@pytest.mark.slow
def test_the_slow_rows_are_signed_again():
    """The four rows `test_every_row_is_signed_again` leaves out, five
    more trees of height 10: XMSS-SHA2_10_256 at its first and last leaf,
    and XMSSMT-SHA2_20/2_256 from leaf 1023 on to 1024. 8.2 seconds
    measured, against 33.6 for the test that always runs, on the release
    build `scripts/build_python.py` makes. Run with
    `pytest --run-slow pytests/test_xmss.py`.

    The paths are the cheap test's: the same tree, signing and
    authentication path code at height 10 (every XMSS set at a random
    leaf), and a lowest tree's last leaf followed by the next tree's
    first, the case 1023 to 1024 covers here, at 31 to 32 for XMSS^MT
    with trees of height five. These four signatures are still verified
    on every run, by tests/test_xmss.rs, which verifies every row."""
    selected = [row for row in rows("sign") if _is_slow(row)]
    assert len(selected) == 4
    _sign_again(selected)


def test_other_derivations_verify_and_changed_signatures_do_not():
    for row in rows("rfc8391"):
        check = allcrypt.xmssmt_verify if row["kind"] == "xmssmt" else allcrypt.xmss_verify
        assert check(row["public"], row["msg"], row["sig"]), row["set"]
    for row in rows("bad"):
        check = allcrypt.xmssmt_verify if row["kind"] == "xmssmt" else allcrypt.xmss_verify
        assert not check(row["public"], row["msg"], row["sig"]), row["what"]


def test_the_key_moves_on_and_reads_back():
    key = allcrypt.XmssKey.from_seeds("XMSSMT-SHA2_20/4_192", bytes(24), bytes(range(24)),
                                      bytes(24), 31)
    public = key.public_bytes()
    first = key.sign(b"one")
    saved = key.to_bytes()
    second = key.sign(b"two")
    assert key.index == 33 and key.remaining == (1 << 20) - 33
    restored = allcrypt.XmssKey.from_bytes(saved, multi_tree=True)
    assert restored.index == 32 and restored.sign(b"two") == second
    assert allcrypt.xmssmt_verify(public, b"one", first)
    assert not allcrypt.xmss_verify(public, b"one", first)
    with pytest.raises(ValueError):
        allcrypt.XmssKey.from_bytes(saved)


@pytest.mark.parametrize("args", [
    ("XMSS-SHA2_10_257", bytes(32), bytes(32), bytes(32)),
    ("XMSS-SHA2_10_256", bytes(31), bytes(32), bytes(32)),
    ("XMSS-SHA2_10_256", bytes(32), bytes(32), bytes(24)),
])
def test_bad_parameters_are_refused(args):
    with pytest.raises(ValueError):
        allcrypt.XmssKey.from_seeds(*args)
