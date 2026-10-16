"""Threefish through the Python bindings. The Rust tests hold the rows of
vectors/threefish.vec, on which Crypto++, Bouncy Castle and Skein3Fish
agree; this checks the binding: the three names and their aliases, the
single blocks through `Cipher` with the key alone and with the tweak
after it, one iterated row of each, every mode, and the refused key
lengths."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "threefish.vec")
# Each name: its block, which is its key length too, and its published rows.
NAMES = {"threefish256": (32, 2), "threefish512": (64, 6), "threefish1024": (128, 2)}


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def key_of(fields):
    """The key alone, or the key followed by the tweak, as the row was
    asked."""
    return bytes.fromhex(fields["key"] + fields.get("tweak", ""))


def test_threefish_is_in_the_catalogue():
    for name in NAMES:
        assert name in allcrypt.block_ciphers_available
        assert getattr(allcrypt.BlockCipher, name.upper()) == name
    # No AEAD here takes a block this wide.
    assert not any(a.startswith("threefish") for a in allcrypt.aeads_available)


@pytest.mark.parametrize("alias,name", [("Threefish-256", "threefish256"),
                                        ("threefish-512", "threefish512"),
                                        ("THREEFISH-1024", "threefish1024")])
def test_the_aliases(alias, name):
    block, _ = NAMES[name]
    key = bytes(range(block))
    assert (allcrypt.Cipher(alias, key).encrypt("ecb", bytes(block))
            == allcrypt.Cipher(name, key).encrypt("ecb", bytes(block)))


@pytest.mark.parametrize("name", NAMES)
def test_vectors_through_cipher(name):
    block, want_published = NAMES[name]
    count = published = tweaked = 0
    for fields in rows(name):
        cipher = allcrypt.Cipher(name, key_of(fields))
        pt = bytes.fromhex(fields["pt"])
        assert cipher.block_size == block
        assert cipher.encrypt("ecb", pt).hex() == fields["ct"], fields
        assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, fields
        count += 1
        published += fields.get("src") == "published"
        tweaked += "tweak" in fields
    assert count >= 250
    assert tweaked >= 150
    assert published == want_published


@pytest.mark.parametrize("name", NAMES)
def test_one_iterated_row_through_cipher(name):
    fields = next(f for f in rows(name + "-iter") if f["n"] == "1000" and "tweak" in f)
    cipher = allcrypt.Cipher(name, key_of(fields))
    block = bytes.fromhex(fields["pt"])
    for _ in range(1000):
        block = cipher.encrypt("ecb", block)
    assert block.hex() == fields["ct"]


@pytest.mark.parametrize("name", NAMES)
def test_every_mode_round_trips(name):
    block, _ = NAMES[name]
    message = bytes(range(256)) * 2
    for length in (block, block + 16):
        for mode in allcrypt.modes_available:
            cipher = allcrypt.Cipher(name, bytes(range(length)))
            iv = None if mode == "ecb" else bytes(block)
            out = (cipher.encrypt(mode, message) if iv is None
                   else cipher.encrypt(mode, message, iv=iv))
            back = (cipher.decrypt(mode, out) if iv is None
                    else cipher.decrypt(mode, out, iv=iv))
            assert back == message, (mode, length)


@pytest.mark.parametrize("name,length", [(n, length) for n, (block, _) in NAMES.items()
                                         for length in (0, 16, 31, 33, 47, 49, 63, 65, 79, 81,
                                                        96, 127, 129, 143, 145, 160)
                                         if length not in (block, block + 16)])
def test_other_key_lengths_are_refused(name, length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher(name, bytes(length))
