"""Anubis through the Python bindings. The Rust tests hold the rows of
vectors/anubis.vec, which libtomcrypt, the Linux kernel and the
designers' reference agree on; this checks the binding: the names, the
single blocks through `Cipher`, one iterated row, every mode, the AEADs,
and the refused key lengths."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "anubis.vec")


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_anubis_is_in_the_catalogues():
    assert "anubis" in allcrypt.block_ciphers_available
    assert allcrypt.BlockCipher.ANUBIS == "anubis"
    for aead in ("anubis-eax", "anubis-mgm", "anubis-ocb"):
        assert aead in allcrypt.aeads_available


def test_anubis_vectors_through_cipher():
    count = published = 0
    for fields in rows("anubis"):
        key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
        cipher = allcrypt.Cipher("anubis", key)
        assert cipher.encrypt("ecb", pt).hex() == fields["ct"], fields
        assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, fields
        count += 1
        published += fields.get("src") == "published"
    assert count >= 2000
    assert published == 19


def test_one_iterated_row_through_cipher():
    fields = next(f for f in rows("anubis-iter") if f["n"] == "1000")
    cipher = allcrypt.Cipher("anubis", bytes.fromhex(fields["key"]))
    block = bytes.fromhex(fields["pt"])
    for _ in range(1000):
        block = cipher.encrypt("ecb", block)
    assert block.hex() == fields["ct"]


def test_anubis_every_mode_round_trips():
    message = bytes(range(64))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher("anubis", bytes(40))
        iv = None if mode == "ecb" else bytes(16)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


def test_anubis_aeads_round_trip():
    for name in ("anubis-eax", "anubis-mgm", "anubis-ocb"):
        nonce = bytes(16) if name.endswith("mgm") else bytes(12)
        sealed = allcrypt.Aead(bytes(28), name).encrypt(nonce, b"message", b"header")
        assert allcrypt.Aead(bytes(28), name).decrypt(nonce, sealed, b"header") == b"message"


@pytest.mark.parametrize("length", [0, 8, 12, 15, 17, 18, 39, 44, 64])
def test_anubis_refuses_other_key_lengths(length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("anubis", bytes(length))
