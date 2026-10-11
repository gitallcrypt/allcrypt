"""MARS through the Python bindings. The Rust tests hold the rows of
vectors/mars.vec, which Crypto++ and Botan agree on, and the Monte Carlo
tests; this checks the binding: the names, the single blocks through
`Cipher` at every key length, one short Monte Carlo test, every mode,
the AEADs, and the refused key lengths."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "mars.vec")


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_mars_is_in_the_catalogues():
    assert "mars" in allcrypt.block_ciphers_available
    assert allcrypt.BlockCipher.MARS == "mars"
    for aead in ("mars-eax", "mars-mgm", "mars-ocb"):
        assert aead in allcrypt.aeads_available


def test_mars_vectors_through_cipher():
    lengths = set()
    count = 0
    for fields in rows("mars"):
        key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
        cipher = allcrypt.Cipher("mars", key)
        assert cipher.encrypt("ecb", pt).hex() == fields["ct"], fields
        assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, fields
        lengths.add(len(key))
        count += 1
    assert count >= 600
    assert lengths == set(range(16, 57, 4))


def test_one_short_monte_carlo_through_cipher():
    """Crypto++'s Monte Carlo procedure with eight keys of 5,000 blocks,
    at the longest key: each key after the first is derived from the
    output, through the binding."""
    fields = next(f for f in rows("mars-mct")
                  if f["outer"] == "8" and len(f["key"]) == 112)
    key, block = bytearray.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
    out = b""
    for _ in range(int(fields["outer"])):
        cipher = allcrypt.Cipher("mars", bytes(key))
        out = b""
        for _ in range(int(fields["inner"])):
            block = cipher.encrypt("ecb", block)
            out = (out + block)[-64:]
        for i, b in enumerate(out[-len(key):]):
            key[i] ^= b
    assert block.hex() == fields["ct"]


def test_mars_every_mode_round_trips():
    message = bytes(range(64))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher("mars", bytes(36))
        iv = None if mode == "ecb" else bytes(16)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


def test_mars_aeads_round_trip():
    for name in ("mars-eax", "mars-mgm", "mars-ocb"):
        nonce = bytes(16) if name.endswith("mgm") else bytes(12)
        sealed = allcrypt.Aead(bytes(56), name).encrypt(nonce, b"message", b"header")
        assert allcrypt.Aead(bytes(56), name).decrypt(nonce, sealed, b"header") == b"message"


@pytest.mark.parametrize("length", [0, 8, 12, 15, 17, 18, 30, 60, 64])
def test_mars_refuses_other_key_lengths(length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("mars", bytes(length))
