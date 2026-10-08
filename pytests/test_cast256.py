"""CAST-256 through the Python bindings. The Rust tests hold RFC 2612's
appendix and 410 Bouncy Castle rows (vectors/cast256.vec); this checks
the binding: the names, the vectors through `Cipher`, every mode, the
AEADs, and the refused key lengths."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "cast256.vec")


def test_cast256_is_in_the_catalogues():
    assert "cast256" in allcrypt.block_ciphers_available
    assert allcrypt.BlockCipher.CAST256 == "cast256"
    for aead in ("cast256-eax", "cast256-mgm", "cast256-ocb"):
        assert aead in allcrypt.aeads_available


def test_cast6_is_the_same_cipher():
    key = bytes(range(24))
    assert (allcrypt.Cipher("cast6", key).encrypt("ecb", bytes(16))
            == allcrypt.Cipher("cast256", key).encrypt("ecb", bytes(16)))


def test_cast256_vectors_through_cipher():
    rows = 0
    with open(VECTORS) as f:
        for line in f:
            if not line.startswith("cast256 "):
                continue
            fields = dict(w.split("=", 1) for w in line.split()[1:])
            key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
            cipher = allcrypt.Cipher("cast256", key)
            assert cipher.encrypt("ecb", pt).hex() == fields["ct"], line
            assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, line
            rows += 1
    assert rows >= 400


def test_cast256_every_mode_round_trips():
    message = bytes(range(64))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher("cast256", bytes(20))
        iv = None if mode == "ecb" else bytes(16)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


def test_cast256_aeads_round_trip():
    for name in ("cast256-eax", "cast256-mgm", "cast256-ocb"):
        nonce = bytes(16) if name.endswith("mgm") else bytes(12)
        sealed = allcrypt.Aead(bytes(32), name).encrypt(nonce, b"message", b"header")
        assert allcrypt.Aead(bytes(32), name).decrypt(nonce, sealed, b"header") == b"message"


@pytest.mark.parametrize("length", [0, 8, 15, 17, 21, 33])
def test_cast256_refuses_other_key_lengths(length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("cast256", bytes(length))
