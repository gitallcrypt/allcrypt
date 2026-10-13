"""Strumok through the Python bindings. The Rust tests hold every row of
vectors/strumok.vec, which UAPKI and uacrypt agree on; this checks the
binding: the name, the keystream rows through `StreamCipher` whole and
in pieces, the refused key and IV lengths, and the refused seek."""

import hashlib
import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "strumok.vec")


def rows():
    with open(VECTORS) as f:
        for line in f:
            if line.startswith("strumok "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_strumok_is_in_the_catalogue():
    assert "strumok" in allcrypt.stream_ciphers_available
    assert allcrypt.StreamCipherName.STRUMOK == "strumok"


def test_strumok_vectors_through_stream_cipher():
    sources = {}
    for f in rows():
        if "keystream" not in f:
            continue
        key, iv = bytes.fromhex(f["key"]), bytes.fromhex(f["iv"])
        want = f["keystream"]
        n = len(want) // 2
        assert allcrypt.StreamCipher("strumok", key, iv).update(bytes(n)).hex() == want, f
        pieces = allcrypt.StreamCipher("strumok", key, iv)
        got = b"".join(pieces.update(bytes(min(11, n - i))) for i in range(0, n, 11))
        assert got.hex() == want, f
        sources[f["source"]] = sources.get(f["source"], 0) + 1
    assert sources == {"standard": 8, "uapki": 9, "letter": 2, "both": 1314}


def test_a_long_keystream():
    long = [f for f in rows() if "sha256" in f]
    assert len(long) == 2
    for f in long:
        c = allcrypt.StreamCipher("strumok", bytes.fromhex(f["key"]), bytes.fromhex(f["iv"]))
        z = c.update(bytes(int(f["length"])))
        assert hashlib.sha256(z).hexdigest() == f["sha256"]


def test_encrypt_and_decrypt_are_the_keystream():
    key, iv = bytes(range(64)), bytes(range(32))
    c = allcrypt.StreamCipher("strumok", key, iv)
    assert c.keystream
    ct = c.encrypt(b"attack at dawn")
    assert allcrypt.StreamCipher("strumok", key, iv).decrypt(ct) == b"attack at dawn"


@pytest.mark.parametrize("key_len,iv_len", [(16, 32), (31, 32), (48, 32), (32, 16), (64, 0)])
def test_wrong_lengths_are_refused(key_len, iv_len):
    with pytest.raises(ValueError):
        allcrypt.StreamCipher("strumok", bytes(key_len), bytes(iv_len))


def test_strumok_does_not_seek():
    c = allcrypt.StreamCipher("strumok", bytes(32), bytes(32))
    with pytest.raises(ValueError):
        c.seek(8)
    with pytest.raises(ValueError):
        allcrypt.StreamCipher("strumok", bytes(32), bytes(32), counter=1)
