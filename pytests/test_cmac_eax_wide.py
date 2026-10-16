"""CMAC and EAX over 160 to 1024 bit blocks through the Python binding.
The Rust test holds every row of vectors/cmac_eax_wide.vec; this checks
the binding on all of them, and that block sizes with no field
polynomial are still refused."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "cmac_eax_wide.vec")


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield line, {k: v for k, v in (w.split("=", 1) for w in line.split()[1:])}


def test_cmac_rows():
    count = 0
    for line, r in rows("cmac"):
        tag = allcrypt.cmac(r["cipher"], unhex(r["key"]), unhex(r["msg"]))
        assert tag.hex() == r["tag"], line
        count += 1
    assert count >= 90


def test_eax_rows():
    count = 0
    for line, r in rows("eax"):
        key, nonce, ad = unhex(r["key"]), unhex(r["nonce"]), unhex(r["ad"])
        name = r["cipher"] + "-eax"
        sealed = allcrypt.Aead(key, name).encrypt(nonce, unhex(r["pt"]), ad)
        assert sealed.hex() == (unhex(r["ct"]) + unhex(r["tag"])).hex(), line
        assert allcrypt.Aead(key, name).decrypt(nonce, sealed, ad) == unhex(r["pt"])
        forged = sealed[:-1] + bytes([sealed[-1] ^ 1])
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.Aead(key, name).decrypt(nonce, forged, ad)
        count += 1
    assert count >= 80


@pytest.mark.parametrize("cipher,key_len", [("simon48", 9), ("speck96", 12),
                                            ("simon32", 8)])
def test_a_block_with_no_field_is_refused(cipher, key_len):
    with pytest.raises(allcrypt.CryptoError, match="bit block"):
        allcrypt.cmac(cipher, bytes(key_len), b"m")
