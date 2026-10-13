"""Khazad through the Python bindings. The Rust tests hold the rows of
vectors/khazad.vec, which libtomcrypt and the Linux kernel agree on;
this checks the binding: the names, the single blocks through `Cipher`,
one iterated row, every mode, the AEADs, and the refused key lengths."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "khazad.vec")


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_khazad_is_in_the_catalogues():
    assert "khazad" in allcrypt.block_ciphers_available
    assert allcrypt.BlockCipher.KHAZAD == "khazad"
    for aead in ("khazad-eax", "khazad-mgm"):
        assert aead in allcrypt.aeads_available


def test_khazad_vectors_through_cipher():
    count = published = 0
    for fields in rows("khazad"):
        key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
        cipher = allcrypt.Cipher("khazad", key)
        assert cipher.encrypt("ecb", pt).hex() == fields["ct"], fields
        assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, fields
        count += 1
        published += fields.get("src") == "published"
    assert count >= 500
    assert published == 10


def test_one_iterated_row_through_cipher():
    fields = next(f for f in rows("khazad-iter") if f["n"] == "1000")
    cipher = allcrypt.Cipher("khazad", bytes.fromhex(fields["key"]))
    block = bytes.fromhex(fields["pt"])
    for _ in range(1000):
        block = cipher.encrypt("ecb", block)
    assert block.hex() == fields["ct"]


def test_khazad_every_mode_round_trips():
    message = bytes(range(64))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher("khazad", bytes(16))
        iv = None if mode == "ecb" else bytes(8)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


def test_khazad_aeads_round_trip():
    for name in ("khazad-eax", "khazad-mgm"):
        nonce = bytes(8)
        sealed = allcrypt.Aead(bytes(16), name).encrypt(nonce, b"message", b"header")
        assert allcrypt.Aead(bytes(16), name).decrypt(nonce, sealed, b"header") == b"message"


@pytest.mark.parametrize("length", [0, 8, 15, 17, 24, 32])
def test_khazad_refuses_other_key_lengths(length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("khazad", bytes(length))
