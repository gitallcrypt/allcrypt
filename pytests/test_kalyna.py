"""Kalyna (DSTU 7624:2014) through the Python bindings. The Rust tests
hold the breakage checks; this checks the binding: the names, every row
of vectors/kalyna.vec through `Cipher`, every mode, and the refusals."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "kalyna.vec")
NAMES = ["kalyna-128", "kalyna-256", "kalyna-512"]
VARIANTS = [("kalyna-128", 16), ("kalyna-128", 32), ("kalyna-256", 32),
            ("kalyna-256", 64), ("kalyna-512", 64)]


def test_kalyna_is_in_the_catalogue():
    for name in NAMES:
        assert name in allcrypt.block_ciphers_available
    assert allcrypt.BlockCipher.KALYNA_512 == "kalyna-512"


def test_vectors_through_cipher():
    rows = 0
    with open(VECTORS) as f:
        for line in f:
            if not line.startswith("kalyna "):
                continue
            fields = dict(w.split("=", 1) for w in line.split()[1:])
            name = f"kalyna-{8 * int(fields['block'])}"
            key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
            cipher = allcrypt.Cipher(name, key)
            assert cipher.encrypt("ecb", pt).hex() == fields["ct"], line
            assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, line
            rows += 1
    assert rows == 85


@pytest.mark.parametrize("name,key_len", VARIANTS)
def test_every_mode_round_trips(name, key_len):
    cipher = allcrypt.Cipher(name, bytes(range(key_len)))
    block = cipher.block_size
    assert block == int(name.split("-")[1]) // 8
    message = bytes(range(3 * block))
    for mode in allcrypt.modes_available:
        c = allcrypt.Cipher(name, bytes(range(key_len)))
        if mode == "ecb":
            assert c.decrypt(mode, c.encrypt(mode, message)) == message
        else:
            out = c.encrypt(mode, message, iv=bytes(block))
            assert c.decrypt(mode, out, iv=bytes(block)) == message, mode


@pytest.mark.parametrize("name,length", [("kalyna-128", 24), ("kalyna-256", 16),
                                         ("kalyna-512", 32), ("kalyna-512", 128)])
def test_other_key_lengths_are_refused(name, length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher(name, bytes(length))
