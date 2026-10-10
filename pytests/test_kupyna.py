"""Kupyna (DSTU 7564:2014) through the Python bindings: the three
catalogue sizes against every row of vectors/kupyna.vec that has them,
and HMAC over it."""

import os

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "kupyna.vec")


def test_kupyna_is_in_the_catalogue():
    for bits in (256, 384, 512):
        assert f"kupyna{bits}" in allcrypt.algorithms_available
        h = allcrypt.new(f"kupyna{bits}")
        assert h.digest_size == bits // 8
        assert h.name == f"kupyna{bits}"


def test_vectors():
    rows = 0
    with open(VECTORS) as f:
        for line in f:
            if not line.startswith("kupyna "):
                continue
            fields = dict(w.split("=", 1) for w in line.split()[1:])
            if fields["bits"] not in ("256", "384", "512"):
                continue
            msg = b"" if fields["msg"] == "-" else bytes.fromhex(fields["msg"])
            h = allcrypt.new(f"kupyna{fields['bits']}")
            for i in range(0, len(msg), 50):
                h.update(msg[i:i + 50])
            assert h.hexdigest() == fields["digest"], line
            rows += 1
    assert rows >= 70


def manual_hmac(name, block, key, msg):
    if len(key) > block:
        key = allcrypt.new(name, key).digest()
    key = key.ljust(block, b"\0")
    inner = allcrypt.new(name, bytes(k ^ 0x36 for k in key) + msg).digest()
    return allcrypt.new(name, bytes(k ^ 0x5C for k in key) + inner).digest()


def test_hmac_uses_the_block_size():
    # 64 bytes for Kupyna-256, 128 above; a 100-byte key is hashed first
    # under the narrow one and padded under the wide ones.
    key = bytes(range(100))
    for name, block in (("kupyna256", 64), ("kupyna384", 128), ("kupyna512", 128)):
        assert (allcrypt.Hmac(key, b"message", name).digest()
                == manual_hmac(name, block, key, b"message")), name
