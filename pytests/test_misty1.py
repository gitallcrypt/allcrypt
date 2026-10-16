"""MISTY1 through the Python bindings. The Rust tests hold the rows of
vectors/misty1.vec, which Botan and Crypt::Misty1 agree on, and RFC
2994's examples; this checks the binding: the names, the single blocks through `Cipher`, one iterated
row, every mode, the AEADs, and the refused key lengths."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "misty1.vec")


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_misty1_is_in_the_catalogues():
    assert "misty1" in allcrypt.block_ciphers_available
    assert allcrypt.BlockCipher.MISTY1 == "misty1"
    for aead in ("misty1-eax", "misty1-mgm"):
        assert aead in allcrypt.aeads_available


def test_misty1_vectors_through_cipher():
    count = published = 0
    for fields in rows("misty1"):
        key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
        cipher = allcrypt.Cipher("misty1", key)
        assert cipher.encrypt("ecb", pt).hex() == fields["ct"], fields
        assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, fields
        count += 1
        published += fields.get("src") == "published"
    assert count >= 500
    assert published == 31


def test_one_iterated_row_through_cipher():
    fields = next(f for f in rows("misty1-iter") if f["n"] == "1000")
    cipher = allcrypt.Cipher("misty1", bytes.fromhex(fields["key"]))
    block = bytes.fromhex(fields["pt"])
    for _ in range(1000):
        block = cipher.encrypt("ecb", block)
    assert block.hex() == fields["ct"]


def test_misty1_every_mode_round_trips():
    message = bytes(range(64))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher("misty1", bytes(16))
        iv = None if mode == "ecb" else bytes(8)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


def test_misty1_aeads_round_trip():
    for name in ("misty1-eax", "misty1-mgm"):
        nonce = bytes(8)
        sealed = allcrypt.Aead(bytes(16), name).encrypt(nonce, b"message", b"header")
        assert allcrypt.Aead(bytes(16), name).decrypt(nonce, sealed, b"header") == b"message"


@pytest.mark.parametrize("length", [0, 8, 15, 17, 24, 32])
def test_misty1_refuses_other_key_lengths(length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("misty1", bytes(length))
