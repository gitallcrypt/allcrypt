"""Skipjack through the Python bindings. The Rust tests hold the rows of
vectors/skipjack.vec, on which libtomcrypt, Bouncy Castle, Crypto++ and
Botan agree; this checks the binding: both names, the single blocks
through `Cipher`, one iterated row of each, every mode, the AEADs, and
the refused key lengths."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "skipjack.vec")
NAMES = ("skipjack", "skipjack-reversed")


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_skipjack_is_in_the_catalogues():
    for name in NAMES:
        assert name in allcrypt.block_ciphers_available
        for aead in (name + "-eax", name + "-mgm"):
            assert aead in allcrypt.aeads_available
    assert allcrypt.BlockCipher.SKIPJACK == "skipjack"
    assert allcrypt.BlockCipher.SKIPJACK_REVERSED == "skipjack-reversed"


@pytest.mark.parametrize("name,published", [("skipjack", 1), ("skipjack-reversed", 31)])
def test_skipjack_vectors_through_cipher(name, published):
    count = found = 0
    for fields in rows(name):
        key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
        cipher = allcrypt.Cipher(name, key)
        assert cipher.encrypt("ecb", pt).hex() == fields["ct"], fields
        assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, fields
        count += 1
        found += fields.get("src") == "published"
    assert count >= 480
    assert found == published


@pytest.mark.parametrize("name", NAMES)
def test_one_iterated_row_through_cipher(name):
    fields = next(f for f in rows(name + "-iter") if f["n"] == "1000")
    cipher = allcrypt.Cipher(name, bytes.fromhex(fields["key"]))
    block = bytes.fromhex(fields["pt"])
    for _ in range(1000):
        block = cipher.encrypt("ecb", block)
    assert block.hex() == fields["ct"]


def test_the_reversed_order_is_every_string_reversed():
    key, block = bytes(range(1, 11)), bytes(range(20, 28))
    straight = allcrypt.Cipher("skipjack", key[::-1]).encrypt("ecb", block[::-1])
    assert allcrypt.Cipher("skipjack-reversed", key).encrypt("ecb", block) == straight[::-1]


@pytest.mark.parametrize("name", NAMES)
def test_skipjack_every_mode_round_trips(name):
    message = bytes(range(64))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher(name, bytes(10))
        iv = None if mode == "ecb" else bytes(8)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


@pytest.mark.parametrize("name", [n + suffix for n in NAMES for suffix in ("-eax", "-mgm")])
def test_skipjack_aeads_round_trip(name):
    nonce = bytes(8)
    sealed = allcrypt.Aead(bytes(10), name).encrypt(nonce, b"message", b"header")
    assert allcrypt.Aead(bytes(10), name).decrypt(nonce, sealed, b"header") == b"message"


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("length", [0, 8, 9, 11, 16, 20])
def test_skipjack_refuses_other_key_lengths(name, length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher(name, bytes(length))
