"""SAFER+ through the Python bindings. The Rust tests hold the rows of
vectors/saferplus.vec, on which libtomcrypt and libmcrypt agree; this
checks the binding: both names, the single blocks through `Cipher`, one
iterated row of each, every mode, the AEADs, and the refused key
lengths."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "saferplus.vec")
NAMES = ("saferplus", "saferplus-reversed-words")


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_saferplus_is_in_the_catalogues():
    for name in NAMES:
        assert name in allcrypt.block_ciphers_available
        for aead in (name + "-eax", name + "-mgm", name + "-ocb"):
            assert aead in allcrypt.aeads_available
    assert allcrypt.BlockCipher.SAFERPLUS == "saferplus"
    assert allcrypt.BlockCipher.SAFERPLUS_REVERSED_WORDS == "saferplus-reversed-words"


@pytest.mark.parametrize("name,published,least", [("saferplus", 3, 1000),
                                                  ("saferplus-reversed-words", 3, 90)])
def test_saferplus_vectors_through_cipher(name, published, least):
    count = found = 0
    for fields in rows(name):
        key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
        cipher = allcrypt.Cipher(name, key)
        assert cipher.encrypt("ecb", pt).hex() == fields["ct"], fields
        assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, fields
        count += 1
        found += fields.get("src") == "published"
    assert count >= least
    assert found == published


@pytest.mark.parametrize("name", NAMES)
def test_one_iterated_row_through_cipher(name):
    fields = next(f for f in rows(name + "-iter") if f["n"] == "1000")
    cipher = allcrypt.Cipher(name, bytes.fromhex(fields["key"]))
    block = bytes.fromhex(fields["pt"])
    for _ in range(1000):
        block = cipher.encrypt("ecb", block)
    assert block.hex() == fields["ct"]


def reverse_words(data):
    return b"".join(data[i:i + 4] for i in range(len(data) - 4, -1, -4))


def test_the_reversed_order_is_every_word_reversed():
    key, block = bytes(range(1, 33)), bytes(range(40, 56))
    straight = allcrypt.Cipher("saferplus", reverse_words(key)).encrypt("ecb", reverse_words(block))
    assert allcrypt.Cipher("saferplus-reversed-words", key).encrypt("ecb", block) \
        == reverse_words(straight)


@pytest.mark.parametrize("name", NAMES)
def test_saferplus_every_mode_round_trips(name):
    message = bytes(range(64))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher(name, bytes(24))
        iv = None if mode == "ecb" else bytes(16)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


@pytest.mark.parametrize("name", [n + suffix for n in NAMES for suffix in ("-eax", "-mgm", "-ocb")])
def test_saferplus_aeads_round_trip(name):
    nonce = bytes(12) if name.endswith("-ocb") else bytes(16)
    sealed = allcrypt.Aead(bytes(32), name).encrypt(nonce, b"message", b"header")
    assert allcrypt.Aead(bytes(32), name).decrypt(nonce, sealed, b"header") == b"message"


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("length", [0, 8, 15, 17, 20, 31, 33])
def test_saferplus_refuses_other_key_lengths(name, length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher(name, bytes(length))
