"""SHACAL-2 through the Python bindings. The Rust tests hold the rows of
vectors/shacal2.vec, which Crypto++ and Bouncy Castle agree on; this
checks the binding: the name, the single blocks through `Cipher` at
every key length, one iterated row, every mode its block allows, and the
refused key lengths."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "shacal2.vec")


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_shacal2_is_in_the_catalogue():
    assert "shacal2" in allcrypt.block_ciphers_available
    assert allcrypt.BlockCipher.SHACAL2 == "shacal2"
    assert allcrypt.Cipher("shacal2", bytes(16)).block_size == 32


def test_shacal2_vectors_through_cipher():
    count, published, lengths = 0, 0, set()
    for fields in rows("shacal2"):
        key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
        cipher = allcrypt.Cipher("shacal2", key)
        assert cipher.encrypt("ecb", pt).hex() == fields["ct"], fields
        assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, fields
        count += 1
        published += fields.get("src") == "published"
        lengths.add(len(key))
    assert count >= 1300
    assert published == 1043
    assert lengths == set(range(16, 65))


def test_one_iterated_row_through_cipher():
    fields = next(f for f in rows("shacal2-iter") if f["n"] == "1000")
    cipher = allcrypt.Cipher("shacal2", bytes.fromhex(fields["key"]))
    block = bytes.fromhex(fields["pt"])
    for _ in range(1000):
        block = cipher.encrypt("ecb", block)
    assert block.hex() == fields["ct"]


def test_a_short_key_is_the_padded_key():
    key = bytes(range(1, 21))
    block = bytes(range(32))
    assert allcrypt.Cipher("shacal2", key).encrypt("ecb", block) \
        == allcrypt.Cipher("shacal2", key + bytes(44)).encrypt("ecb", block)


def test_shacal2_modes_round_trip():
    message = bytes(range(96))
    ran = 0
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher("shacal2", bytes(64))
        iv = None if mode == "ecb" else bytes(32)
        try:
            out = (cipher.encrypt(mode, message) if iv is None
                   else cipher.encrypt(mode, message, iv=iv))
        except allcrypt.CryptoError:
            continue  # a mode defined for one block size only
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode
        ran += 1
    assert ran >= 6


@pytest.mark.parametrize("length", [0, 8, 15, 65, 128])
def test_shacal2_refuses_other_key_lengths(length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("shacal2", bytes(length))
