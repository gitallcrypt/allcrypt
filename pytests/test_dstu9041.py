"""DSTU 9041:2020 through the Python bindings. The Rust tests hold every
row of vectors/dstu9041.vec, which uacrypt and li0ard agree on; this
checks the binding: the names, the worked examples and a sample of the
rows through Dstu9041Key and Dstu9041PublicKey, lengths in bits, the
refusals, and fresh keys."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "dstu9041.vec")


def rows():
    with open(VECTORS) as f:
        for line in f:
            if line.startswith("dstu9041 "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_the_curves_are_listed():
    assert allcrypt.dstu9041_curves_available == ["dstu9041-e256-1", "dstu9041-e512-1"]


def test_vectors_through_the_keys():
    seen = {}
    for f in rows():
        key = allcrypt.Dstu9041Key.from_private(f["curve"], bytes.fromhex(f["private"]))
        if "refused" in f:
            with pytest.raises(ValueError):
                key.decrypt(bytes.fromhex(f["ciphertext"]))
            kind = "refused"
        elif "ciphertext" in f:
            # Every eighth row of the many: the Rust tests take them all.
            seen["ciphertext"] = seen.get("ciphertext", 0) + 1
            if f["source"] == "both" and seen["ciphertext"] % 8:
                continue
            public = allcrypt.Dstu9041PublicKey(f["curve"], bytes.fromhex(f["public"]))
            message, bits = bytes.fromhex(f["message"]), int(f["bits"])
            ct = public.encrypt(message, bits=bits, epsilon=bytes.fromhex(f["epsilon"]))
            assert ct.hex() == f["ciphertext"], f
            assert key.decrypt_bits(ct) == (message, bits)
            assert key.decrypt(ct) == message
            kind = "ciphertext-" + f["source"]
        else:
            assert key.public_key().public_bytes().hex() == f["public"]
            kind = "public"
        seen[kind] = seen.get(kind, 0) + 1
    assert seen["refused"] == 20
    assert seen["ciphertext-standard"] == 2
    assert seen["ciphertext-uacrypt"] == 14
    assert seen["public"] == 26


@pytest.mark.parametrize("curve", ["dstu9041-e256-1", "dstu9041-e512-1"])
def test_fresh_keys_round_trip(curve):
    key = allcrypt.Dstu9041Key.generate(curve)
    public = key.public_key()
    assert public.curve == key.curve == curve
    width = len(key.private_bytes())
    assert width == {"dstu9041-e256-1": 32, "dstu9041-e512-1": 64}[curve]
    assert len(public.public_bytes()) == 2 * width
    longest = public.max_message_bits // 8
    for message in (b"k", os.urandom(longest)):
        ct = public.encrypt(message)
        assert len(ct) == 4 * width
        assert key.decrypt(ct) == message
    # A random one-time key: the same message twice is two ciphertexts.
    assert public.encrypt(b"same") != public.encrypt(b"same")
    with pytest.raises(ValueError):
        public.encrypt(bytes(longest + 1))
    with pytest.raises(ValueError):
        public.encrypt(b"")


def test_bad_inputs_are_refused():
    key = allcrypt.Dstu9041Key.from_private("E256/1", bytes([0x25]))
    with pytest.raises(ValueError):
        allcrypt.Dstu9041Key.from_private("dstu9041-e256-1", bytes([1]))
    with pytest.raises(ValueError):
        allcrypt.Dstu9041Key.from_private("dstu9041-e384-1", bytes([7]))
    public = key.public_key().public_bytes()
    with pytest.raises(ValueError):
        allcrypt.Dstu9041PublicKey("dstu9041-e256-1", public[:-1] + bytes([public[-1] ^ 1]))
    with pytest.raises(ValueError):
        key.public_key().encrypt(b"\x10", bits=4)
    assert "Dstu9041Key" in repr(key)
