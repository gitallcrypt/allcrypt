"""LOKI97 through the Python bindings. The Rust tests hold the rows of
vectors/loki97.vec, from the designers' reference C and libmcrypt; this
checks the binding: both names, the single blocks through `Cipher`, one
iterated row of each, libmcrypt's form, every mode, the AEADs, and the
refused key lengths."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "loki97.vec")
NAMES = ("loki97", "loki97-mcrypt")


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_loki97_is_in_the_catalogues():
    for name in NAMES:
        assert name in allcrypt.block_ciphers_available
        for aead in (name + "-eax", name + "-mgm", name + "-ocb"):
            assert aead in allcrypt.aeads_available
    assert allcrypt.BlockCipher.LOKI97 == "loki97"
    assert allcrypt.BlockCipher.LOKI97_MCRYPT == "loki97-mcrypt"


@pytest.mark.parametrize("name,published,least", [("loki97", 6, 1000),
                                                  ("loki97-mcrypt", 2, 90)])
def test_loki97_vectors_through_cipher(name, published, least):
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


def swap_word_bytes(data):
    return b"".join(data[i:i + 4][::-1] for i in range(0, len(data), 4))


@pytest.mark.parametrize("length", [16, 24, 32])
def test_libmcrypts_form_is_words_swapped_and_the_key_padded(length):
    key, block = bytes(range(1, length + 1)), bytes(range(40, 56))
    padded = swap_word_bytes(key) + bytes(32 - length)
    straight = allcrypt.Cipher("loki97", padded).encrypt("ecb", swap_word_bytes(block))
    assert allcrypt.Cipher("loki97-mcrypt", key).encrypt("ecb", block) \
        == swap_word_bytes(straight)


@pytest.mark.parametrize("name", NAMES)
def test_loki97_every_mode_round_trips(name):
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
def test_loki97_aeads_round_trip(name):
    nonce = bytes(12) if name.endswith("-ocb") else bytes(16)
    sealed = allcrypt.Aead(bytes(32), name).encrypt(nonce, b"message", b"header")
    assert allcrypt.Aead(bytes(32), name).decrypt(nonce, sealed, b"header") == b"message"


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("length", [0, 8, 15, 17, 20, 31, 33])
def test_loki97_refuses_other_key_lengths(name, length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher(name, bytes(length))
