"""Whirlpool through the Python bindings, against OpenSSL.

The Rust unit tests hold Botan's eleven published vectors and
`scripts/diff_check.py` sweeps three hundred lengths against OpenSSL's
legacy provider. What is checked here is the binding, and the reason
this hash is in the library at all: **TrueCrypt and VeraCrypt derive
their header keys with PBKDF2-HMAC-Whirlpool**, so a volume made with
that option cannot be opened without it - and `hashlib` has never had
it.

OpenSSL 3 moved Whirlpool to the `legacy` provider. That the reference
is one release away from disappearing is why it was implemented while
one still exists, and it is why the test that uses it says so rather
than skipping quietly.
"""

import hashlib
import shutil
import subprocess

import pytest

import allcrypt


def _openssl_whirlpool(data):
    done = subprocess.run(
        ["openssl", "dgst", "-whirlpool", "-provider", "legacy",
         "-provider", "default", "-binary"],
        input=data, capture_output=True)
    if done.returncode != 0:
        return None
    return done.stdout


def _has_openssl_whirlpool():
    return (shutil.which("openssl") is not None
            and _openssl_whirlpool(b"") is not None)


openssl_whirlpool = pytest.mark.skipif(
    not _has_openssl_whirlpool(),
    reason="this OpenSSL has no whirlpool in its legacy provider")


def test_hashlib_still_cannot_do_whirlpool():
    """The premise. If CPython ever gains it, `diff_check.py` should use
    `hashlib` rather than shelling out, and somebody should notice."""
    with pytest.raises(ValueError):
        hashlib.new("whirlpool")
    assert "whirlpool" in allcrypt.algorithms_available


def test_it_is_in_the_catalogue_and_the_enum():
    assert allcrypt.HashName.WHIRLPOOL == "whirlpool"
    assert allcrypt.new("whirlpool").digest_size == 64
    assert allcrypt.new("whirlpool").block_size == 64


def test_the_empty_input():
    """The one value a reader can check against any other
    implementation in a single line."""
    assert allcrypt.new("whirlpool").hexdigest().startswith(
        "19fa61d75522a4669b44e39c1d2e1726")


@openssl_whirlpool
@pytest.mark.parametrize("length", [0, 1, 2, 31, 32, 33, 55, 56, 63, 64, 65,
                                    127, 128, 129, 1000, 4096])
def test_it_agrees_with_openssl(length):
    """Around the block boundary and around 32 bytes short of it, which
    is where the 256 bit length field goes - a message whose padding
    needs a second block is the case a 64 bit field gets wrong."""
    data = bytes((i * 167 + 13) & 0xff for i in range(length))
    assert allcrypt.new("whirlpool", data).digest() == _openssl_whirlpool(data)


@openssl_whirlpool
def test_hmac_whirlpool_agrees_with_a_hand_built_one():
    """`hmac` cannot name Whirlpool either, so the reference is built
    from RFC 2104's definition over OpenSSL's digest - which checks our
    HMAC and our Whirlpool at once.

    **The block and the digest are both 64 bytes here**, so `B == L`:
    a key longer than the block is replaced by its digest, which then
    exactly fills a block. MD2 is the only other algorithm in this
    library where that happens.
    """
    def reference(key, message):
        block = 64
        if len(key) > block:
            key = _openssl_whirlpool(key)
        key = key + b"\x00" * (block - len(key))
        inner = _openssl_whirlpool(bytes(k ^ 0x36 for k in key) + message)
        return _openssl_whirlpool(bytes(k ^ 0x5c for k in key) + inner)

    for key, message in [(b"", b""),
                         (b"key", b"msg"),
                         (b"k" * 63, b"x" * 100),
                         (b"k" * 64, b"x" * 100),
                         (b"k" * 65, b"x" * 100),   # longer than the block
                         (b"k" * 200, b"")]:
        assert (allcrypt.Hmac(key, message, "whirlpool").digest()
                == reference(key, message)), (key, message)


def test_pbkdf2_hmac_whirlpool_is_reachable():
    """The shape a VeraCrypt header key derivation has: PBKDF2 over
    HMAC-Whirlpool, 64 bytes out. Asserted as structure rather than
    against a value, because the only published VeraCrypt vectors are
    whole volume headers."""
    key = allcrypt.pbkdf2_hmac("whirlpool", b"passphrase", bytes(64), 100, 64)
    assert len(key) == 64
    assert key != bytes(64)
    assert key != allcrypt.pbkdf2_hmac("whirlpool", b"passphrase", bytes(64),
                                       101, 64)
    # And a different hash gives a different key, so the name is not
    # being ignored.
    assert key != allcrypt.pbkdf2_hmac("sha512", b"passphrase", bytes(64),
                                       100, 64)


def test_streaming_matches_one_call():
    message = bytes(range(256)) * 3
    for split in [0, 1, 63, 64, 65, 200, len(message)]:
        streamed = allcrypt.new("whirlpool")
        streamed.update(message[:split])
        streamed.update(b"")
        streamed.update(message[split:])
        assert (streamed.hexdigest()
                == allcrypt.new("whirlpool", message).hexdigest()), split


def test_copy_forks_the_state():
    h = allcrypt.new("whirlpool", b"hello ")
    forked = h.copy()
    h.update(b"world")
    forked.update(b"there")
    assert h.hexdigest() == allcrypt.new("whirlpool", b"hello world").hexdigest()
    assert forked.hexdigest() != h.hexdigest()
