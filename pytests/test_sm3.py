"""SM3 against hashlib, which is this OpenSSL underneath.

GB/T 32905-2016. The Rust tests read twenty vectors out of the vendored
`draft-sca-cfrg-sm3-02.txt` - two that the hash standard states itself
and eighteen from the SM2 documents. This file does the part vectors
cannot: every length across the padding boundaries, irregular streaming,
and the constructions built on top of SM3 that a caller will actually
reach for - HMAC, PBKDF2 and HKDF.

**This is a real second opinion**, unlike the GOST hashes. OpenSSL 3.0
implements SM3, so `hashlib.new("sm3")` is an implementation nobody here
wrote. Where that is not true the file says so at the test.
"""

import hashlib
import hmac as stdlib_hmac

import pytest

import allcrypt


def reference(data):
    return hashlib.new("sm3", data).digest()


def test_sm3_is_in_the_catalogue():
    assert "sm3" in allcrypt.algorithms_available


def test_hashlib_really_has_sm3():
    # If this ever stops being true the comparisons below would silently
    # become comparisons with nothing. Same reason `ripemd160`'s row in
    # diff_check.py carries a note: OpenSSL moves algorithms between
    # providers between releases.
    assert "sm3" in hashlib.algorithms_available


@pytest.mark.parametrize("length", list(range(0, 130)) + [255, 256, 257, 1000, 100000])
def test_matches_openssl_at_every_length(length):
    data = bytes((i * 167 + 13) % 256 for i in range(length))
    assert allcrypt.new("sm3", data).digest() == reference(data)


def test_the_sizes_are_what_hmac_needs():
    h = allcrypt.new("sm3")
    assert h.digest_size == 32
    assert h.block_size == 64
    assert h.digest_size == hashlib.new("sm3").digest_size
    assert h.block_size == hashlib.new("sm3").block_size


@pytest.mark.parametrize("chunk", [1, 2, 3, 7, 31, 55, 56, 57, 63, 64, 65, 127, 128])
def test_streaming_in_pieces_equals_one_call(chunk):
    data = bytes((i * 31 + 5) % 256 for i in range(2000))
    h = allcrypt.new("sm3")
    for i in range(0, len(data), chunk):
        h.update(data[i : i + chunk])
    assert h.digest() == reference(data)


def test_digest_can_be_taken_twice_and_updating_continues():
    h = allcrypt.new("sm3", b"abc")
    first = h.hexdigest()
    assert h.hexdigest() == first
    h.update(b"d")
    assert h.digest() == reference(b"abcd")


def test_a_single_bit_changes_the_whole_digest():
    # Not a security claim - an avalanche this coarse would be visible in
    # any working hash. It is here because a digest that ignores part of
    # its input passes every length test above.
    base = bytes(64)
    first = reference(base)
    for bit in range(0, 512, 37):
        altered = bytearray(base)
        altered[bit // 8] ^= 1 << (bit % 8)
        assert allcrypt.new("sm3", bytes(altered)).digest() != first


@pytest.mark.parametrize("key_len", [0, 1, 16, 32, 63, 64, 65, 100])
@pytest.mark.parametrize("msg_len", [0, 1, 64, 200])
def test_hmac_sm3_matches_the_standard_library(key_len, msg_len):
    # RFC 8998's TLS 1.3 suites use HMAC-SM3 in the key schedule, so the
    # block size above has to be right for a key longer than one block -
    # which is the only case that reads it.
    key = bytes((i * 89 + 7) % 256 for i in range(key_len))
    message = bytes((i * 13 + 3) % 256 for i in range(msg_len))
    ours = allcrypt.Hmac(key, message, "sm3").digest()
    assert ours == stdlib_hmac.new(key, message, "sm3").digest()


def test_hmac_sm3_with_a_key_longer_than_a_block_is_hashed_first():
    # The branch that only a >64 byte key reaches. Asserted directly
    # because a wrong block size makes every short-key case above pass.
    long_key = bytes(range(200))
    ours = allcrypt.Hmac(long_key, b"message", "sm3").digest()
    assert ours == stdlib_hmac.new(long_key, b"message", "sm3").digest()
    assert ours == stdlib_hmac.new(reference(long_key), b"message", "sm3").digest()


@pytest.mark.parametrize("iterations", [1, 2, 1000])
def test_pbkdf2_with_sm3_matches_hashlib(iterations):
    out = allcrypt.pbkdf2_hmac("sm3", b"password", b"salt", iterations, 32)
    assert out == hashlib.pbkdf2_hmac("sm3", b"password", b"salt", iterations, 32)


def test_hkdf_with_sm3_round_trips_through_its_own_parts():
    # hashlib has no HKDF, so this is *not* an independent check of HKDF
    # - only that SM3 works underneath it. RFC 5869's structure is
    # checked against python-cryptography for the SHA hashes elsewhere.
    out = allcrypt.hkdf(b"secret", 42, salt=b"salt", info=b"info", digestmod="sm3")
    assert len(out) == 42
    assert out != allcrypt.hkdf(b"secret", 42, salt=b"salt", info=b"info",
                                digestmod="sha256")


def test_sm3_is_not_sha256_by_another_name():
    # They share the padding, the block size and the output length, so a
    # dispatch table with one wrong entry produces something that passes
    # every structural test in this file.
    data = b"the quick brown fox"
    assert allcrypt.new("sm3", data).digest() != allcrypt.new("sha256", data).digest()
