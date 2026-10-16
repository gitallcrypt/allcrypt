"""3-Way through the Python bindings. The Rust tests hold the rows of
vectors/threeway.vec, which Crypto++ and libmcrypt agree on; this checks
the binding: the names and aliases, the single blocks through `Cipher`,
one iterated row, every mode, and the refused key lengths. A 96 bit
block has no EAX, MGM or OCB here."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "threeway.vec")


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_threeway_is_in_the_catalogues():
    assert "threeway" in allcrypt.block_ciphers_available
    assert allcrypt.BlockCipher.THREEWAY == "threeway"
    assert not [a for a in allcrypt.aeads_available if a.startswith("threeway")]
    key, pt = bytes(12), bytes(12)
    expected = allcrypt.Cipher("threeway", key).encrypt("ecb", pt)
    for alias in ("3way", "3-Way"):
        assert allcrypt.Cipher(alias, key).encrypt("ecb", pt) == expected


def test_threeway_vectors_through_cipher():
    count = published = 0
    for fields in rows("threeway"):
        key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
        cipher = allcrypt.Cipher("threeway", key)
        assert cipher.encrypt("ecb", pt).hex() == fields["ct"], fields
        assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, fields
        count += 1
        published += fields.get("src") == "published"
    assert count >= 500
    assert published == 5


def test_one_iterated_row_through_cipher():
    fields = next(f for f in rows("threeway-iter") if f["n"] == "1000")
    cipher = allcrypt.Cipher("threeway", bytes.fromhex(fields["key"]))
    block = bytes.fromhex(fields["pt"])
    for _ in range(1000):
        block = cipher.encrypt("ecb", block)
    assert block.hex() == fields["ct"]


def test_threeway_every_mode_round_trips():
    message = bytes(range(60))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher("threeway", bytes(12))
        iv = None if mode == "ecb" else bytes(12)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


@pytest.mark.parametrize("length", [0, 8, 11, 13, 16, 24, 32])
def test_threeway_refuses_other_key_lengths(length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("threeway", bytes(length))
