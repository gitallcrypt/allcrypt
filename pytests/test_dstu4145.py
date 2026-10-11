"""DSTU 4145-2002 through Python, against the named-curve rows of
`vectors/dstu4145.vec` (Bouncy Castle 1.77 and cryptonite, written by
`scripts/make_dstu4145_vectors.py`), and the facade's encodings and
refusals."""

import pathlib

import pytest

import allcrypt

LINES = [line for line in (pathlib.Path(__file__).resolve().parent.parent / "vectors"
                           / "dstu4145.vec").read_text().splitlines()
         if line and not line.startswith("#")]


def rows(kind):
    out = []
    for line in LINES:
        if line.split()[0] == kind:
            row = dict(field.split("=", 1) for field in line.split()[1:])
            if row["curve"].startswith("dstu4145-"):
                out.append(row)
    return out


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def width(curve):
    # The order's width in bytes, from the private key's encoding.
    return len(allcrypt.Dstu4145Key.from_private(curve, b"\x01").private_bytes())


def test_the_curves_are_the_standards_ten():
    assert allcrypt.dstu4145_curves_available == [
        f"dstu4145-m{m}" for m in (163, 167, 173, 179, 191, 233, 257, 307, 367, 431)]


def test_public_keys_and_compression():
    pubs, packs = rows("pub"), rows("compress")
    assert len(pubs) == 51 and len(packs) == 51
    for row in pubs:
        key = allcrypt.Dstu4145Key.from_private(row["curve"], unhex(row["d"]))
        assert key.public_key().public_bytes() == unhex(row["qx"]) + unhex(row["qy"])
        assert key.curve == row["curve"]
    for row in packs:
        packed = unhex(row["packed"])
        key = allcrypt.Dstu4145PublicKey(row["curve"], packed)
        assert key.public_bytes() == unhex(row["qx"]) + unhex(row["qy"])
        assert key.public_bytes(compressed=True) == packed
        assert allcrypt.Dstu4145PublicKey(row["curve"], key.public_bytes()).public_bytes(
            compressed=True) == packed


def test_signatures_with_the_given_nonce():
    signs = rows("sign")
    assert len(signs) == 30
    for row in signs:
        key = allcrypt.Dstu4145Key.from_private(row["curve"], unhex(row["d"]))
        n = width(row["curve"])
        expected = int(row["s"], 16).to_bytes(n, "big") + int(row["r"], 16).to_bytes(n, "big")
        assert key.sign_with_nonce(unhex(row["hash"]), unhex(row["e"])) == expected
        assert key.public_key().verify(unhex(row["hash"]), expected)


def test_verification():
    checks = rows("verify")
    assert len(checks) == 92
    assert {row["ok"] for row in checks} == {"0", "1"}
    for row in checks:
        key = allcrypt.Dstu4145PublicKey(row["curve"], unhex(row["qx"]) + unhex(row["qy"]))
        n = width(row["curve"])
        r, s = int(row["r"], 16), int(row["s"], 16)
        if max(r, s).bit_length() > 8 * n:
            continue
        signature = s.to_bytes(n, "big") + r.to_bytes(n, "big")
        assert key.verify(unhex(row["hash"]), signature) == (row["ok"] == "1"), row


def test_shared_points():
    points = rows("dh")
    assert len(points) == 21
    for row in points:
        key = allcrypt.Dstu4145Key.from_private(row["curve"], unhex(row["d"]))
        peer = allcrypt.Dstu4145PublicKey(row["curve"], unhex(row["qx"]) + unhex(row["qy"]))
        z = key.shared_point(peer, cofactor=row["cofactor"] == "1")
        assert z == unhex(row["zx"]) + unhex(row["zy"])


@pytest.mark.parametrize("curve", ["dstu4145-m163", "dstu4145-m257"])
def test_a_round_trip_and_the_exchange_agree(curve):
    alice, bob = allcrypt.Dstu4145Key.generate(curve), allcrypt.Dstu4145Key.generate(curve)
    hash_ = bytes(range(32))
    signature = alice.sign(hash_)
    assert len(signature) == 2 * width(curve)
    assert alice.public_key().verify(hash_, signature)
    assert not alice.public_key().verify(hash_[::-1], signature)
    assert not bob.public_key().verify(hash_, signature)
    # Bytes-like inputs, as everywhere else.
    assert alice.public_key().verify(bytearray(hash_), memoryview(signature))
    for cofactor in (False, True):
        assert alice.shared_point(bob.public_key(), cofactor) == \
            bob.shared_point(alice.public_key(), cofactor)
    assert alice.shared_point(bob.public_key(), False) != \
        alice.shared_point(bob.public_key(), True)
    restored = allcrypt.Dstu4145Key.from_private(curve, alice.private_bytes())
    assert restored.public_key().public_bytes() == alice.public_key().public_bytes()


def test_what_is_refused():
    key = allcrypt.Dstu4145Key.generate("dstu4145-m163")
    public = key.public_key().public_bytes()
    with pytest.raises(ValueError, match="Unknown DSTU 4145 curve"):
        allcrypt.Dstu4145Key.generate("dstu4145-m164")
    with pytest.raises(ValueError, match=r"\[1, n\)"):
        allcrypt.Dstu4145Key.from_private("dstu4145-m163", b"\x00")
    with pytest.raises(ValueError, match="two halves"):
        key.public_key().verify(b"h" * 32, b"\x01" * 41)
    with pytest.raises(ValueError, match="compressed or"):
        allcrypt.Dstu4145PublicKey("dstu4145-m163", public[:-1])
    off = public[:-1] + bytes([public[-1] ^ 1])
    with pytest.raises(ValueError, match="not on the curve"):
        allcrypt.Dstu4145PublicKey("dstu4145-m163", off)
    other = allcrypt.Dstu4145Key.generate("dstu4145-m167").public_key()
    with pytest.raises(ValueError, match="peer's key is on dstu4145-m167"):
        key.shared_point(other)
    with pytest.raises(ValueError, match="nonce"):
        key.sign_with_nonce(b"h" * 32, b"\x00")
