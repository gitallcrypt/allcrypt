"""MD2 and MD4 through the Python bindings.

The Rust unit tests hold RFC 1319's and RFC 1320's published vectors,
parsed out of the documents, and `scripts/diff_check.py` sweeps 304
lengths of each against independent implementations. What is checked
here is the binding and the things a *caller* trips over:

- neither hash is in `hashlib`, so the reason to reach for this library
  is that the standard one cannot do it at all;
- MD4 is reachable from OpenSSL's legacy provider, which is a real
  second opinion available on this machine and is used as one;
- **MD2's block size is 16**, where every other hash here is 64 or more,
  and HMAC has to cope with `B == L`.

MD2 has no independent implementation anywhere on this machine. That is
stated rather than worked around: the rows that would need one are in
`scripts/diff_check.py` against a second reading of RFC 1319, and this
file does not pretend otherwise.
"""

import hashlib
import shutil
import subprocess

import pytest

import allcrypt


# --------------------------------------------------- why they are here ---

def test_neither_is_in_hashlib():
    """The premise. If a future CPython gained them, the openssl-based
    checks below would become second-guessing rather than evidence, and
    somebody should notice."""
    for name in ("md2", "md4"):
        with pytest.raises(ValueError):
            hashlib.new(name)
        assert name in allcrypt.algorithms_available


def test_they_are_in_the_generated_name_enum():
    assert allcrypt.HashName.MD2 == "md2"
    assert allcrypt.HashName.MD4 == "md4"


# ------------------------------------------------- MD4 against OpenSSL ---

def _openssl_md4(data):
    """OpenSSL's MD4, from the legacy provider."""
    done = subprocess.run(
        ["openssl", "dgst", "-md4", "-provider", "legacy",
         "-provider", "default", "-binary"],
        input=data, capture_output=True)
    if done.returncode != 0:
        return None
    return done.stdout


def _has_openssl_md4():
    return shutil.which("openssl") is not None and _openssl_md4(b"") is not None


openssl_md4 = pytest.mark.skipif(not _has_openssl_md4(),
                                 reason="this OpenSSL has no legacy MD4")


@openssl_md4
@pytest.mark.parametrize("length", [0, 1, 2, 3, 55, 56, 57, 63, 64, 65,
                                    119, 120, 127, 128, 129, 200, 1000])
def test_md4_agrees_with_openssl(length):
    """Every length around a block boundary and around the point where
    the padding needs a second block.

    55 and 56 bracket the case a 32-bit length field gets wrong, which
    is the SHA-1 bug this repository actually shipped.
    """
    data = bytes((i * 167 + 13) & 0xff for i in range(length))
    assert allcrypt.new("md4", data).digest() == _openssl_md4(data)


@openssl_md4
def test_hmac_md4_agrees_with_a_hand_built_one_over_openssl():
    """`hmac` cannot name MD4 either, so the reference is built from
    RFC 2104's definition over OpenSSL's digest. That checks our HMAC
    and our MD4 at once, which is the combination `pbkdf2_hmac("md4")`
    and MS-CHAPv2 actually use."""
    def reference(key, message):
        block = 64
        if len(key) > block:
            key = _openssl_md4(key)
        key = key + b"\x00" * (block - len(key))
        inner = _openssl_md4(bytes(k ^ 0x36 for k in key) + message)
        return _openssl_md4(bytes(k ^ 0x5c for k in key) + inner)

    for key, message in [(b"", b""),
                         (b"key", b"msg"),
                         (b"k" * 63, b"x" * 100),
                         (b"k" * 64, b"x" * 100),
                         (b"k" * 65, b"x" * 100),      # key longer than block
                         (b"k" * 200, b"")]:
        assert (allcrypt.Hmac(key, message, "md4").digest()
                == reference(key, message)), (key, message)


# -------------------------------------------------- MD2's odd geometry ---

def test_md2_reports_a_sixteen_byte_block():
    """Every other hash here is 64 or more. This is not a bug and not a
    truncation - MD2's compression function takes sixteen bytes, and a
    caller sizing a buffer from `block_size` needs to know."""
    assert allcrypt.new("md2").block_size == 16
    assert allcrypt.new("md2").digest_size == 16
    assert allcrypt.new("md4").block_size == 64

    smallest = min(allcrypt.new(name).block_size
                   for name in allcrypt.algorithms_available)
    assert smallest == 16, "MD2 should be the smallest block in the catalogue"


def test_hmac_md2_works_where_the_block_equals_the_digest():
    """HMAC needs `B >= L`, and MD2 is the one place here where they are
    equal rather than B being larger. The degenerate case is legal and
    has to actually run - a key longer than sixteen bytes is replaced by
    its own digest, which then exactly fills a block.

    There is no RFC for HMAC-MD2 and nothing on this machine computes
    one, so this asserts structure rather than a value: it is built from
    RFC 2104's definition using our own MD2, which the Rust vectors
    pin.
    """
    def reference(key, message):
        block = 16
        if len(key) > block:
            key = allcrypt.new("md2", key).digest()
        key = key + b"\x00" * (block - len(key))
        inner = allcrypt.new("md2", bytes(k ^ 0x36 for k in key) + message)
        return allcrypt.new(
            "md2", bytes(k ^ 0x5c for k in key) + inner.digest()).digest()

    for key in [b"", b"k", b"k" * 15, b"k" * 16, b"k" * 17, b"k" * 100]:
        assert allcrypt.Hmac(key, b"message", "md2").digest() \
            == reference(key, b"message"), key

    # And two different keys must give two different tags, which a
    # reference sharing our bug would also satisfy - so this is the
    # weakest of the three checks and is here only to catch a key that
    # was ignored entirely.
    assert (allcrypt.Hmac(b"a", b"m", "md2").digest()
            != allcrypt.Hmac(b"b", b"m", "md2").digest())


def test_md2_pads_an_aligned_message_with_a_whole_block():
    """MD2's padding is PKCS#7's rule: always 1..16 bytes. So sixteen
    bytes of input and those same bytes followed by sixteen `0x10`s are
    different messages, and an implementation that skipped the padding
    on an aligned input would make them the same."""
    aligned = b"A" * 16
    assert (allcrypt.new("md2", aligned).hexdigest()
            != allcrypt.new("md2", aligned + bytes([0x10]) * 16).hexdigest())


# --------------------------------------------------------- the bindings ---

@pytest.mark.parametrize("name", ["md2", "md4"])
def test_streaming_matches_one_call(name):
    """The bug shape this repository has had twice: a buffered hash that
    desynchronises after the second call. Checked through the binding
    because `update` crosses the GIL boundary and takes a different path
    from the constructor."""
    message = bytes(range(256)) * 3
    for split in [0, 1, 15, 16, 17, 63, 64, 65, 200, len(message)]:
        streamed = allcrypt.new(name)
        streamed.update(message[:split])
        streamed.update(b"")
        streamed.update(message[split:])
        assert (streamed.hexdigest()
                == allcrypt.new(name, message).hexdigest()), split


@pytest.mark.parametrize("name", ["md2", "md4"])
def test_copy_forks_the_state(name):
    h = allcrypt.new(name, b"hello ")
    forked = h.copy()
    h.update(b"world")
    forked.update(b"there")
    assert h.hexdigest() == allcrypt.new(name, b"hello world").hexdigest()
    assert forked.hexdigest() == allcrypt.new(name, b"hello there").hexdigest()


@pytest.mark.parametrize("name", ["md2", "md4"])
def test_they_take_any_buffer_like_every_other_argument(name):
    """The rule from `pytests/test_byte_inputs.py`, spot-checked on the
    two algorithms added since it was written."""
    assert (allcrypt.new(name, bytearray(b"abc")).hexdigest()
            == allcrypt.new(name, memoryview(b"abc")).hexdigest()
            == allcrypt.new(name, b"abc").hexdigest())


@pytest.mark.parametrize("name", ["md2", "md4"])
def test_pbkdf2_accepts_them(name):
    """`pbkdf2_hmac` takes any hash in the catalogue, and MD2's short
    block is the case most likely to have been special."""
    out = allcrypt.pbkdf2_hmac(name, b"password", b"salt", 100, 40)
    assert len(out) == 40
    assert out != bytes(40)
    assert out != allcrypt.pbkdf2_hmac(name, b"password", b"salt", 101, 40)
