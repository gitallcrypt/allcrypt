"""The Chaskey-LTS block cipher through the Python bindings. The Rust tests
hold the rows of vectors/chaskey_lts.vec; this checks the binding: the
name, the single blocks through `Cipher`, one iterated row, every mode of
operation, the AEADs, and the refused key lengths."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "chaskey_lts.vec")


def rows():
    with open(VECTORS) as f:
        for line in f:
            if line.startswith("chaskey-lts "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_chaskey_lts_is_in_the_catalogues():
    assert "chaskey-lts" in allcrypt.block_ciphers_available
    for aead in ("eax", "mgm", "ocb"):
        assert f"chaskey-lts-{aead}" in allcrypt.aeads_available
    assert allcrypt.BlockCipher.CHASKEY_LTS == "chaskey-lts"


def test_chaskey_lts_vectors_through_cipher():
    count = 0
    for fields in rows():
        if "times" in fields:
            continue
        key, block = bytes.fromhex(fields["key"]), bytes.fromhex(fields["block"])
        cipher = allcrypt.Cipher("chaskey-lts", key)
        assert cipher.encrypt("ecb", block).hex() == fields["out"], fields
        assert cipher.decrypt("ecb", bytes.fromhex(fields["out"])) == block, fields
        count += 1
    assert count == 577


def test_one_iterated_row_through_cipher():
    fields = next(f for f in rows() if f.get("times") == "1000")
    cipher = allcrypt.Cipher("chaskey-lts", bytes.fromhex(fields["key"]))
    block = bytes.fromhex(fields["block"])
    for _ in range(1000):
        block = cipher.encrypt("ecb", block)
    assert block.hex() == fields["out"]


def test_chaskey_lts_every_mode_round_trips():
    message = bytes(range(64))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher("chaskey-lts", bytes(16))
        iv = None if mode == "ecb" else bytes(16)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


def test_chaskey_lts_aeads_round_trip():
    for aead in ("eax", "mgm", "ocb"):
        nonce = bytes(16) if aead == "mgm" else bytes(12)
        full = f"chaskey-lts-{aead}"
        sealed = allcrypt.Aead(bytes(16), full).encrypt(nonce, b"message", b"header")
        assert allcrypt.Aead(bytes(16), full).decrypt(nonce, sealed, b"header") == b"message"


@pytest.mark.parametrize("length", [0, 8, 15, 17, 24, 32])
def test_chaskey_lts_refuses_other_key_lengths(length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("chaskey-lts", bytes(length))
