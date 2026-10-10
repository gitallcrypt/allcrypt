"""Rijndael through the Python bindings. The Rust tests hold the 275
rows of vectors/rijndael.vec and the breakage of each size; this checks
the binding: the names, the vectors through `Cipher`, every mode at each
block size, and what is refused."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "rijndael.vec")
NAMES = ["rijndael-128", "rijndael-160", "rijndael-192", "rijndael-224", "rijndael-256"]


def test_rijndael_is_in_the_catalogue():
    for name in NAMES:
        assert name in allcrypt.block_ciphers_available
    assert allcrypt.BlockCipher.RIJNDAEL_256 == "rijndael-256"
    # No AEAD: their constants are defined for 64 and 128 bit blocks.
    assert not any(a.startswith("rijndael") for a in allcrypt.aeads_available)


def test_block_sizes():
    for name in NAMES:
        bits = int(name.split("-")[1])
        assert allcrypt.Cipher(name, bytes(16)).block_size == bits // 8


def test_rijndael_vectors_through_cipher():
    rows = 0
    with open(VECTORS) as f:
        for line in f:
            if not line.startswith("rijndael "):
                continue
            fields = dict(w.split("=", 1) for w in line.split()[1:])
            name = f"rijndael-{8 * int(fields['block'])}"
            key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
            cipher = allcrypt.Cipher(name, key)
            assert cipher.encrypt("ecb", pt).hex() == fields["ct"], line
            assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, line
            rows += 1
    assert rows == 275


def test_a_128_bit_block_is_aes():
    for key in (bytes(range(16)), bytes(range(24)), bytes(range(32))):
        assert (allcrypt.Cipher("rijndael-128", key).encrypt("ecb", bytes(32))
                == allcrypt.Cipher("aes", key).encrypt("ecb", bytes(32)))


@pytest.mark.parametrize("name", NAMES)
def test_every_mode_round_trips(name):
    block = allcrypt.Cipher(name, bytes(20)).block_size
    message = bytes(range(4 * block))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher(name, bytes(20))
        iv = None if mode == "ecb" else bytes(block)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


def test_a_sixteen_byte_iv_is_refused_for_a_wide_block():
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("rijndael-256", bytes(32)).encrypt("cbc", bytes(64), iv=bytes(16))


@pytest.mark.parametrize("length", [0, 8, 15, 17, 21, 33])
def test_other_key_lengths_are_refused(length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("rijndael-256", bytes(length))
