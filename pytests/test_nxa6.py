"""256-NEA6, 256-NIA6 and 256-NCA6 through the Python binding. The Rust
tests hold the specification's test data and every row of
vectors/zuc256_3gpp.vec; this checks the binding on the rows, its
keyword arguments, its byte inputs and the refusals."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "zuc256_3gpp.vec")


def rows():
    with open(VECTORS) as f:
        for line in f:
            if not line.startswith("#"):
                kind, *fields = line.split()
                yield kind, dict(w.split("=", 1) for w in fields)


def raw(value):
    return b"" if value == "-" else bytes.fromhex(value)


def test_witness_rows():
    counts = {}
    for kind, r in rows():
        counts[kind] = counts.get(kind, 0) + 1
        if counts[kind] > 120:
            continue
        common = (raw(r["key"]), int(r["count"]), int(r["bearer"]), int(r["direction"]))
        extra = raw(r["extra_iv"])
        bits = int(r["bits"])
        data = raw(r["data"])
        if kind == "nea":
            assert allcrypt.nea6(*common, data, bits=bits, extra_iv=extra) == raw(r["out"])
        elif kind == "nia":
            assert allcrypt.nia6(*common, data, mac_bytes=int(r["mac_bytes"]), bits=bits,
                                 extra_iv=extra) == raw(r["mac"])
        elif kind == "nca":
            got = allcrypt.nca6_encrypt(*common, data, mac_bytes=int(r["mac_bytes"]),
                                        aad=raw(r["aad"]), bits=bits,
                                        aad_bits=int(r["aad_bits"]), extra_iv=extra)
            assert got == (raw(r["out"]), raw(r["mac"]))
        else:
            call = lambda: allcrypt.nca6_decrypt(*common, data, raw(r["mac"]), aad=raw(r["aad"]),
                                                 bits=bits, aad_bits=int(r["aad_bits"]),
                                                 extra_iv=extra)
            if r["refused"] == "1":
                with pytest.raises(ValueError, match="does not match"):
                    call()
            else:
                assert call() == raw(r["out"])
    assert set(counts) == {"nea", "nia", "nca", "ncad"}


def test_defaults_and_buffers():
    key = bytes(range(32))
    data = bytearray(b"a 5G message")
    # Whole bytes and no EXTRA_IV by default; any buffer of bytes.
    assert allcrypt.nea6(key, 7, 3, 1, data) == allcrypt.nea6(
        memoryview(key), 7, 3, 1, bytes(data), bits=8 * len(data), extra_iv=bytes(6))
    sealed, mac = allcrypt.nca6_encrypt(key, 7, 3, 1, data, mac_bytes=8, aad=b"header")
    assert len(mac) == 8
    assert allcrypt.nca6_decrypt(key, 7, 3, 1, sealed, mac, aad=b"header") == bytes(data)
    # A 16 byte key is zero-extended, and IV's LK bit set: not the same as
    # the 32 byte key with zeros.
    short = key[:16]
    assert allcrypt.nea6(short, 7, 3, 1, data) != allcrypt.nea6(short + bytes(16), 7, 3, 1,
                                                                 data)
    assert allcrypt.nia6(key, 7, 3, 1, data, mac_bytes=16)[:4] != allcrypt.nia6(
        key, 7, 3, 1, data, mac_bytes=4)


def test_refusals():
    key = bytes(32)
    with pytest.raises(ValueError, match="32 bytes"):
        allcrypt.nea6(bytes(20), 0, 0, 0, b"x")
    with pytest.raises(ValueError, match="BEARER"):
        allcrypt.nea6(key, 0, 32, 0, b"x")
    with pytest.raises(ValueError, match="EXTRA_IV"):
        allcrypt.nea6(key, 0, 0, 0, b"x", extra_iv=b"12345")
    with pytest.raises(ValueError, match="MAC_BYTES"):
        allcrypt.nia6(key, 0, 0, 0, b"x", mac_bytes=17)
    with pytest.raises(TypeError):
        allcrypt.nia6(key, 0, 0, 0, b"x")
    sealed, mac = allcrypt.nca6_encrypt(key, 0, 0, 0, b"x", mac_bytes=4)
    with pytest.raises(ValueError, match="does not match"):
        allcrypt.nca6_decrypt(key, 0, 0, 0, sealed, bytes(4))


def test_the_stream_cipher_name():
    assert "zuc256-3gpp" in allcrypt.stream_ciphers_available
