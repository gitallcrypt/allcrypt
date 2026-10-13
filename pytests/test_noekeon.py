"""Noekeon through the Python bindings, in both key modes. The Rust tests
hold the rows of vectors/noekeon.vec; this checks the binding: the
names, the single blocks through `Cipher` in each mode, one iterated row
each, every mode of operation, the AEADs, and the refused key lengths."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "noekeon.vec")
NAMES = ("noekeon", "noekeon-indirect")


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_noekeon_is_in_the_catalogues():
    for name in NAMES:
        assert name in allcrypt.block_ciphers_available
        for aead in ("eax", "mgm", "ocb"):
            assert f"{name}-{aead}" in allcrypt.aeads_available
    assert allcrypt.BlockCipher.NOEKEON == "noekeon"


@pytest.mark.parametrize("name,published", [("noekeon", 8), ("noekeon-indirect", 11)])
def test_noekeon_vectors_through_cipher(name, published):
    count = seen = 0
    for fields in rows(name):
        key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
        cipher = allcrypt.Cipher(name, key)
        assert cipher.encrypt("ecb", pt).hex() == fields["ct"], fields
        assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, fields
        count += 1
        seen += fields.get("src") == "published"
    assert count >= 580
    assert seen == published


@pytest.mark.parametrize("name", NAMES)
def test_one_iterated_row_through_cipher(name):
    fields = next(f for f in rows(name + "-iter") if f["n"] == "1000")
    cipher = allcrypt.Cipher(name, bytes.fromhex(fields["key"]))
    block = bytes.fromhex(fields["pt"])
    for _ in range(1000):
        block = cipher.encrypt("ecb", block)
    assert block.hex() == fields["ct"]


@pytest.mark.parametrize("name", NAMES)
def test_noekeon_every_mode_round_trips(name):
    message = bytes(range(64))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher(name, bytes(16))
        iv = None if mode == "ecb" else bytes(16)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


@pytest.mark.parametrize("name", NAMES)
def test_noekeon_aeads_round_trip(name):
    for aead in ("eax", "mgm", "ocb"):
        nonce = bytes(16) if aead == "mgm" else bytes(12)
        full = f"{name}-{aead}"
        sealed = allcrypt.Aead(bytes(16), full).encrypt(nonce, b"message", b"header")
        assert allcrypt.Aead(bytes(16), full).decrypt(nonce, sealed, b"header") == b"message"


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("length", [0, 8, 15, 17, 24, 32])
def test_noekeon_refuses_other_key_lengths(name, length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher(name, bytes(length))
