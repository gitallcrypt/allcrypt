"""RC6 through the Python bindings. The Rust tests hold the vectors
(vectors/rc6.vec: the submission's six and 513 from Bouncy Castle); this
checks the binding: the catalogue, a vector through `Cipher`, every mode,
the AEADs, and the key lengths refused."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "rc6.vec")


def test_rc6_is_in_the_catalogues():
    assert "rc6" in allcrypt.block_ciphers_available
    assert allcrypt.BlockCipher.RC6 == "rc6"
    for aead in ("rc6-eax", "rc6-mgm", "rc6-ocb"):
        assert aead in allcrypt.aeads_available


def test_rc6_vectors_through_cipher():
    rows = 0
    with open(VECTORS) as f:
        for line in f:
            if not line.startswith("rc6 "):
                continue
            fields = dict(w.split("=", 1) for w in line.split()[1:])
            key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
            cipher = allcrypt.Cipher("rc6", key)
            assert cipher.encrypt("ecb", pt).hex() == fields["ct"], line
            assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, line
            rows += 1
    assert rows > 500


def test_rc6_every_mode_round_trips():
    message = bytes(range(64))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher("rc6", bytes(24))
        iv = None if mode == "ecb" else bytes(16)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


def test_rc6_aeads_round_trip():
    for name in ("rc6-eax", "rc6-mgm", "rc6-ocb"):
        nonce = bytes(16) if name == "rc6-mgm" else bytes(12)
        sealed = allcrypt.Aead(bytes(16), name).encrypt(nonce, b"message", b"header")
        assert allcrypt.Aead(bytes(16), name).decrypt(nonce, sealed, b"header") == b"message"


@pytest.mark.parametrize("length", [0, 256, 300])
def test_rc6_refuses_key_lengths_outside_1_to_255(length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("rc6", bytes(length))
