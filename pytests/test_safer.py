"""SAFER through the Python bindings. The Rust tests hold the rows of
vectors/safer.vec, on which libtomcrypt, Crypto++ and Botan agree; this
checks the binding: the four names, the round count as the parameter,
the rows through `Cipher`, one iterated row, every mode, the AEADs, and
the refused key lengths and round counts."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "safer.vec")
VARIANTS = {"safer-k64": (8, 6), "safer-k128": (16, 10), "safer-sk64": (8, 8),
            "safer-sk128": (16, 10)}


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_safer_is_in_the_catalogues():
    for name in VARIANTS:
        assert name in allcrypt.block_ciphers_available
        for aead in (name + "-eax", name + "-mgm"):
            assert aead in allcrypt.aeads_available
    assert allcrypt.BlockCipher.SAFER_SK128 == "safer-sk128"


@pytest.mark.parametrize("name,published", [("safer-k64", 5), ("safer-k128", 4),
                                            ("safer-sk64", 5), ("safer-sk128", 17)])
def test_safer_vectors_through_cipher(name, published):
    count = found = 0
    for fields in rows(name):
        key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
        cipher = allcrypt.Cipher(name, key, fields["rounds"])
        assert cipher.encrypt("ecb", pt).hex() == fields["ct"], fields
        assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, fields
        count += 1
        found += fields.get("src") == "published"
    assert count >= 580
    assert found == published


@pytest.mark.parametrize("name", VARIANTS)
def test_no_parameter_is_the_usual_round_count(name):
    keylen, usual = VARIANTS[name]
    fields = next(f for f in rows(name) if f["rounds"] == str(usual))
    key = bytes.fromhex(fields["key"])
    assert allcrypt.Cipher(name, key).encrypt("ecb", bytes.fromhex(fields["pt"])).hex() \
        == fields["ct"]


def test_one_iterated_row_through_cipher():
    fields = next(f for f in rows("safer-sk128-iter") if f["n"] == "1000")
    cipher = allcrypt.Cipher("safer-sk128", bytes.fromhex(fields["key"]), fields["rounds"])
    block = bytes.fromhex(fields["pt"])
    for _ in range(1000):
        block = cipher.encrypt("ecb", block)
    assert block.hex() == fields["ct"]


@pytest.mark.parametrize("name", VARIANTS)
def test_safer_every_mode_round_trips(name):
    message = bytes(range(64))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher(name, bytes(VARIANTS[name][0]))
        iv = None if mode == "ecb" else bytes(8)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


@pytest.mark.parametrize("name", [n + suffix for n in VARIANTS for suffix in ("-eax", "-mgm")])
def test_safer_aeads_round_trip(name):
    key = bytes(VARIANTS[name.rsplit("-", 1)[0]][0])
    nonce = bytes(8)
    sealed = allcrypt.Aead(key, name).encrypt(nonce, b"message", b"header")
    assert allcrypt.Aead(key, name).decrypt(nonce, sealed, b"header") == b"message"


@pytest.mark.parametrize("name", VARIANTS)
def test_safer_refuses_other_key_lengths_and_round_counts(name):
    keylen = VARIANTS[name][0]
    for length in (0, 7, 9, 15, 17, 24):
        if length != keylen:
            with pytest.raises(allcrypt.CryptoError):
                allcrypt.Cipher(name, bytes(length))
    for rounds in ("0", "14", "ten"):
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.Cipher(name, bytes(keylen), rounds)
