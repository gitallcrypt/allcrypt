"""VMAC through the Python binding. The Rust test holds every row of
vectors/vmac.vec; this checks the binding on all of them, the default
cipher, and the refusals."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "vmac.vec")


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def message(field):
    if field.startswith("r") and ":" in field:
        count, unit = field[1:].split(":")
        return bytes.fromhex(unit) * int(count)
    return unhex(field)


def test_vmac_rows():
    count = 0
    with open(VECTORS) as f:
        for line in f:
            if not line.startswith("vmac "):
                continue
            r = dict(w.split("=", 1) for w in line.split()[1:])
            tag = allcrypt.vmac(unhex(r["key"]), unhex(r["nonce"]), message(r["msg"]),
                                tag_len=len(r["tag"]) // 2, cipher=r["cipher"])
            assert tag.hex() == r["tag"], line
            count += 1
    assert count >= 200


def test_aes_is_the_default():
    key, nonce = b"abcdefghijklmnop", b"bcdefghi"
    assert allcrypt.vmac(key, nonce, b"abc") == allcrypt.vmac(key, nonce, b"abc", cipher="aes")
    assert allcrypt.vmac(key, nonce, b"abc").hex() == "2d376cf5b1813ce5"


@pytest.mark.parametrize("nonce", [b"", bytes(17), b"\x80" + bytes(15)])
def test_a_bad_nonce_is_refused(nonce):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.vmac(bytes(16), nonce, b"m")


@pytest.mark.parametrize("tag_len", [4, 12, 32])
def test_other_tag_lengths_are_refused(tag_len):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.vmac(bytes(16), b"n", b"m", tag_len=tag_len)


def test_a_64_bit_cipher_is_refused():
    with pytest.raises(allcrypt.CryptoError, match="128 bit block"):
        allcrypt.vmac(bytes(8), b"n", b"m", cipher="des")
