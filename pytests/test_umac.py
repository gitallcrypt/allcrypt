"""UMAC (RFC 4418) from Python.

`tests/test_umac_nettle.rs` is the real check: every row of Nettle's file,
up to 32 MB. This file covers the binding: that `allcrypt.umac` reaches the
same code, takes any byte buffer, and refuses what RFC 4418 does not
define rather than guessing.
"""

import pathlib

import pytest

import allcrypt

VECTORS = pathlib.Path(__file__).resolve().parent.parent / "vectors" / "umac_nettle.vec"


def message(seed, length):
    # The generator's stream: byte i is the top byte of (i + seed) * 0x9E3779B1 mod 2^32.
    return bytes(((i + seed) * 0x9E3779B1 & 0xFFFFFFFF) >> 24 for i in range(length))


def records():
    found, current = [], {}
    for line in VECTORS.read_text().splitlines():
        if line.startswith("#") or line.startswith("["):
            continue
        if not line.strip():
            if current:
                found.append(current)
            current = {}
            continue
        key, value = line.split(" = ")
        current[key] = value
    if current:
        found.append(current)
    return found


def test_nettles_tags_for_the_short_messages():
    rows = [r for r in records() if int(r["length"]) <= 4096]
    assert len(rows) > 600
    for row in rows:
        tag = allcrypt.umac(bytes.fromhex(row["key"]), bytes.fromhex(row["nonce"]),
                            message(int(row["seed"]), int(row["length"])),
                            tag_len=int(row["bytes"]))
        assert tag.hex() == row["tag"], row


def test_any_contiguous_buffer_is_the_same_message():
    key, nonce, data = b"abcdefghijklmnop", b"bcdefghi", b"abc" * 500
    expected = allcrypt.umac(key, nonce, data)
    assert expected.hex() == "d4cf26ddefd5c01a"
    assert allcrypt.umac(bytearray(key), memoryview(nonce), bytearray(data)) == expected


@pytest.mark.parametrize("key, nonce, tag_len", [
    (bytes(15), b"n", 8),        # AES-128 only
    (bytes(32), b"n", 8),
    (bytes(16), b"", 8),         # a nonce is 1 to 16 bytes
    (bytes(16), bytes(17), 8),
    (bytes(16), b"n", 0),        # 4, 8, 12 or 16
    (bytes(16), b"n", 6),
    (bytes(16), b"n", 20),
])
def test_what_rfc_4418_does_not_define_is_refused(key, nonce, tag_len):
    with pytest.raises(ValueError):
        allcrypt.umac(key, nonce, b"data", tag_len=tag_len)
