"""LRW through the Python surface, against IEEE P1619's vectors as the
Linux kernel carries them (`vectors/lrw_aes.vec`)."""

import pathlib

import pytest

import allcrypt

VECTORS = pathlib.Path(__file__).resolve().parent.parent / "vectors" / "lrw_aes.vec"


def records():
    out = []
    for block in VECTORS.read_text().split("\nname = ")[1:]:
        fields = dict(line.split(" = ", 1) for line in block.splitlines()[1:] if " = " in line)
        fields["name"] = block.splitlines()[0]
        out.append(fields)
    return out


@pytest.mark.parametrize("record", records(), ids=lambda r: r["name"][:24])
def test_ieee_vectors(record):
    key = bytes.fromhex(record["key"])
    index = int(record["iv"], 16)
    plaintext = bytes.fromhex(record["plaintext"])
    ciphertext = bytes.fromhex(record["ciphertext"])
    assert allcrypt.lrw_encrypt(key, index, plaintext) == ciphertext
    assert allcrypt.lrw_decrypt(key, index, ciphertext) == plaintext


def test_whole_blocks_and_a_tweak_key_are_required():
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.lrw_encrypt(bytes(32), 0, bytes(17))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.lrw_encrypt(bytes(16), 0, bytes(16))
    with pytest.raises(allcrypt.CryptoError, match="block"):
        allcrypt.lrw_encrypt(bytes(24), 0, bytes(16), cipher="des")


def test_the_index_counts_blocks():
    """Encrypting two blocks at index i equals encrypting each alone at
    i and i + 1."""
    key = bytes(range(48))
    data = bytes(range(32))
    whole = allcrypt.lrw_encrypt(key, 1000, data, cipher="twofish")
    assert whole[:16] == allcrypt.lrw_encrypt(key, 1000, data[:16], cipher="twofish")
    assert whole[16:] == allcrypt.lrw_encrypt(key, 1001, data[16:], cipher="twofish")
