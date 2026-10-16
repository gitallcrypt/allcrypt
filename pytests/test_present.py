"""PRESENT through the Python bindings. The Rust tests hold the rows of
vectors/present.vec, on which PRESENT.go, kurtfu/present and OpenTitan's
Python PRESENT agree; this checks the binding: the name, the single
blocks through `Cipher`, one iterated row, every mode, the AEADs, and
the refused key lengths."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "present.vec")
# Each name: its block, its key lengths, its published rows, its AEADs.
NAMES = {"present": (8, (10, 16), 9, ("-eax", "-mgm"))}


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_present_is_in_the_catalogues():
    for name, (_, _, _, aeads) in NAMES.items():
        assert name in allcrypt.block_ciphers_available
        assert getattr(allcrypt.BlockCipher, name.upper()) == name
        for suffix in aeads:
            assert name + suffix in allcrypt.aeads_available
    # A 64 bit block has no OCB.
    assert "present-ocb" not in allcrypt.aeads_available


@pytest.mark.parametrize("name", NAMES)
def test_vectors_through_cipher(name):
    block, lengths, want_published, _ = NAMES[name]
    count = published = 0
    for fields in rows(name):
        key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
        cipher = allcrypt.Cipher(name, key)
        assert cipher.block_size == block
        assert cipher.encrypt("ecb", pt).hex() == fields["ct"], fields
        assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, fields
        count += 1
        published += fields.get("src") == "published"
    assert count >= 590
    assert published == want_published


@pytest.mark.parametrize("name", NAMES)
def test_one_iterated_row_through_cipher(name):
    fields = next(f for f in rows(name + "-iter") if f["n"] == "1000")
    cipher = allcrypt.Cipher(name, bytes.fromhex(fields["key"]))
    block = bytes.fromhex(fields["pt"])
    for _ in range(1000):
        block = cipher.encrypt("ecb", block)
    assert block.hex() == fields["ct"]


@pytest.mark.parametrize("name", NAMES)
def test_every_mode_round_trips(name):
    block, lengths, _, _ = NAMES[name]
    message = bytes(range(64))
    for length in lengths:
        for mode in allcrypt.modes_available:
            cipher = allcrypt.Cipher(name, bytes(length))
            iv = None if mode == "ecb" else bytes(block)
            out = (cipher.encrypt(mode, message) if iv is None
                   else cipher.encrypt(mode, message, iv=iv))
            back = (cipher.decrypt(mode, out) if iv is None
                    else cipher.decrypt(mode, out, iv=iv))
            assert back == message, (mode, length)


@pytest.mark.parametrize("name,suffix", [(n, s) for n, v in NAMES.items() for s in v[3]])
def test_aeads_round_trip(name, suffix):
    block, lengths, _, _ = NAMES[name]
    nonce = bytes(12) if suffix == "-ocb" else bytes(block)
    key = bytes(lengths[-1])
    sealed = allcrypt.Aead(key, name + suffix).encrypt(nonce, b"message", b"header")
    assert allcrypt.Aead(key, name + suffix).decrypt(nonce, sealed, b"header") == b"message"


@pytest.mark.parametrize("name,length", [(n, length) for n, v in NAMES.items()
                                         for length in (0, 8, 11, 13, 15, 17, 20, 23, 25, 31, 33)
                                         if length not in v[1]])
def test_other_key_lengths_are_refused(name, length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher(name, bytes(length))
