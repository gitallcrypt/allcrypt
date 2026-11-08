"""SNOW 3G, ZUC and the 3GPP modes through the Python binding. The Rust
test holds the published test data and every row of
vectors/snow3g_zuc.vec; this checks the binding on the rows, its byte
inputs and the refusals."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "snow3g_zuc.vec")


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
        key = bytes.fromhex(r["key"])
        if kind == "stream":
            want = raw(r["keystream"])
            got = allcrypt.StreamCipher(r["cipher"], key, bytes.fromhex(r["iv"])).encrypt(
                bytes(len(want)))
        elif kind == "f8":
            want = raw(r["result"])
            got = allcrypt.mobile_cipher(r["alg"], key, int(r["count"], 16), int(r["bearer"]),
                                         int(r["direction"]), raw(r["data"]), int(r["bits"]))
        elif kind == "f9" and r["alg"] == "uia2":
            want = bytes.fromhex(r["mac"])
            got = allcrypt.uia2(key, int(r["count"], 16), int(r["fresh"], 16),
                                int(r["direction"]), raw(r["data"]), int(r["bits"]))
        elif kind == "f9":
            want = bytes.fromhex(r["mac"])
            got = allcrypt.mobile_mac(r["alg"], key, int(r["count"], 16), int(r["fresh"]),
                                      int(r["direction"]), raw(r["data"]), int(r["bits"]))
        else:
            want = bytes.fromhex(r["mac"])
            got = allcrypt.zuc_mac(key, bytes.fromhex(r["iv"]), raw(r["data"]),
                                   tag_bits=int(r["tag"]), bits=int(r["bits"]))
        assert got == want, f"{kind} {r}"[:200]
        counts[kind] = counts.get(kind, 0) + 1
    assert counts == {"stream": 78, "f8": 192, "f9": 223, "zucmac": 128}


@pytest.mark.parametrize("name", ["snow3g", "zuc128", "zuc256"])
def test_the_names_are_listed(name):
    assert name in allcrypt.stream_ciphers_available
    assert allcrypt.StreamCipherName(name) == name


def test_the_mode_names_are_listed():
    assert allcrypt.mobile_ciphers_available == ["uea1", "uea2", "eea1", "nea1", "eea3", "nea3"]
    assert allcrypt.mobile_macs_available == ["eia1", "nia1", "eia3", "nia3"]


def test_the_whole_message_is_the_default():
    key, data = bytes(range(16)), bytes(range(40))
    for name in allcrypt.mobile_ciphers_available:
        assert allcrypt.mobile_cipher(name, key, 1, 2, 0, data) == \
            allcrypt.mobile_cipher(name, key, 1, 2, 0, data, 320)
    for name in allcrypt.mobile_macs_available:
        assert allcrypt.mobile_mac(name, key, 1, 2, 0, data) == \
            allcrypt.mobile_mac(name, key, 1, 2, 0, data, 320)
    assert allcrypt.uia2(key, 1, 2, 0, data) == allcrypt.uia2(key, 1, 2, 0, data, 320)


def test_any_contiguous_buffer_is_taken():
    key, data = bytes(range(16)), bytes(range(37))
    want = allcrypt.mobile_cipher("eea3", key, 7, 3, 1, data, 290)
    for wrap in (bytearray, memoryview):
        assert allcrypt.mobile_cipher("eea3", wrap(key), 7, 3, 1, wrap(data), 290) == want
    tag = allcrypt.zuc_mac(bytes(32), bytes(25), data, tag_bits=64)
    assert allcrypt.zuc_mac(bytearray(32), memoryview(bytes(25)), bytearray(data),
                            tag_bits=64) == tag


@pytest.mark.parametrize("call", [
    lambda: allcrypt.mobile_cipher("uea2", bytes(16), 0, 32, 0, b"x"),
    lambda: allcrypt.mobile_cipher("eea3", bytes(16), 0, 0, 2, b"x"),
    lambda: allcrypt.mobile_cipher("eea3", bytes(15), 0, 0, 0, b"x"),
    lambda: allcrypt.mobile_cipher("eea3", bytes(16), 0, 0, 0, b"xy", 17),
    lambda: allcrypt.mobile_cipher("eea2", bytes(16), 0, 0, 0, b"x"),
    lambda: allcrypt.mobile_mac("uia2", bytes(16), 0, 0, 0, b"x"),
    lambda: allcrypt.uia2(bytes(16), 0, 0, 2, b"x"),
    lambda: allcrypt.zuc_mac(bytes(16), bytes(16), b"x", tag_bits=64),
    lambda: allcrypt.zuc_mac(bytes(32), bytes(25), b"x", tag_bits=48),
    lambda: allcrypt.zuc_mac(bytes(32), bytes(24), b"x"),
    lambda: allcrypt.StreamCipher("zuc256", bytes(32), bytes(17) + b"\x40" + bytes(7)),
    lambda: allcrypt.StreamCipher("snow3g", bytes(16), bytes(12)),
])
def test_bad_inputs_are_refused(call):
    with pytest.raises(allcrypt.CryptoError):
        call()
