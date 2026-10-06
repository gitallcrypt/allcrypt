"""AES Key Wrap against python-cryptography, which is OpenSSL underneath.

The Rust tests run RFC 3394 section 4's six vectors and RFC 5649 section
6's two, read out of the vendored documents. What they cannot cover is
the lengths the RFCs do not happen to use, and the property that matters
most here is a *negative* one: a wrapping that has been altered must not
unwrap. So this file sweeps every length both forms accept and then
alters every byte of every wrapping.

Key wrap has no IV and no nonce, so the comparison with OpenSSL is byte
for byte rather than mutual acceptance - the same reason EdDSA's is.
"""

import pytest

from cryptography.hazmat.primitives import keywrap

import allcrypt


KEKS = [bytes(range(16)), bytes(range(24)), bytes(range(32))]


def name_for(kek):
    return f"aes{len(kek) * 8}"


@pytest.mark.parametrize("kek", KEKS, ids=name_for)
@pytest.mark.parametrize("length", [16, 24, 32, 40, 64, 128, 256])
def test_wrapping_matches_openssl(kek, length):
    data = bytes((i * 5 + length) % 256 for i in range(length))
    assert allcrypt.key_wrap(kek, data) == keywrap.aes_key_wrap(kek, data)


@pytest.mark.parametrize("kek", KEKS, ids=name_for)
@pytest.mark.parametrize("length", [16, 24, 40, 64])
def test_we_unwrap_what_openssl_wraps(kek, length):
    data = bytes((i * 3 + 1) % 256 for i in range(length))
    wrapped = keywrap.aes_key_wrap(kek, data)
    assert allcrypt.key_unwrap(kek, wrapped) == data


@pytest.mark.parametrize("kek", KEKS, ids=name_for)
def test_padded_wrapping_matches_openssl_at_every_length(kek):
    """RFC 5649 covers 1 byte upwards, and the boundary at eight bytes is
    a *different algorithm* - one block skips the six passes entirely."""
    for length in range(1, 81):
        data = bytes((i * 11 + length) % 256 for i in range(length))
        ours = allcrypt.key_wrap_with_padding(kek, data)
        theirs = keywrap.aes_key_wrap_with_padding(kek, data)
        assert ours == theirs, f"length {length}"
        assert allcrypt.key_unwrap_with_padding(kek, theirs) == data, f"length {length}"


def test_the_single_block_boundary_is_crossed():
    """Eight bytes or fewer wraps to sixteen; nine wraps to twenty-four.

    Asserted rather than assumed, because the two sizes are produced by
    different code and a test sweeping only long keys never reaches the
    short one."""
    kek = bytes(range(16))
    assert len(allcrypt.key_wrap_with_padding(kek, b"\x01")) == 16
    assert len(allcrypt.key_wrap_with_padding(kek, bytes(8))) == 16
    assert len(allcrypt.key_wrap_with_padding(kek, bytes(9))) == 24


@pytest.mark.parametrize("kek", KEKS, ids=name_for)
def test_every_altered_byte_is_refused(kek):
    """The integrity check is what replaces a MAC, so it is the property
    to hammer. OpenSSL refuses the same wrappings, and the test asserts
    that too - otherwise this measures our own opinion of itself."""
    data = bytes(range(32))
    wrapped = allcrypt.key_wrap(kek, data)
    for index in range(len(wrapped)):
        broken = bytearray(wrapped)
        broken[index] ^= 1 << (index % 8)
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.key_unwrap(kek, bytes(broken))
        with pytest.raises(keywrap.InvalidUnwrap):
            keywrap.aes_key_unwrap(kek, bytes(broken))


@pytest.mark.parametrize("length", [1, 7, 8, 9, 16, 20, 33])
def test_every_altered_byte_of_a_padded_wrapping_is_refused(length):
    kek = bytes(range(24))
    data = bytes(range(length))
    wrapped = allcrypt.key_wrap_with_padding(kek, data)
    for index in range(len(wrapped)):
        broken = bytearray(wrapped)
        broken[index] ^= 0x80
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.key_unwrap_with_padding(kek, bytes(broken))


def test_the_wrong_key_is_refused():
    kek = bytes(range(16))
    other = bytes(range(1, 17))
    wrapped = allcrypt.key_wrap(kek, bytes(32))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.key_unwrap(other, wrapped)


def test_wrapping_is_deterministic():
    """No IV, no nonce. Two copies of one key must look like two copies,
    which is what lets a wrapped key be compared and deduplicated."""
    kek = bytes(range(32))
    data = bytes(range(40))
    assert allcrypt.key_wrap(kek, data) == allcrypt.key_wrap(kek, data)


@pytest.mark.parametrize("length", [0, 1, 7, 8, 9, 15, 17, 23])
def test_the_unpadded_form_refuses_what_it_cannot_represent(length):
    """RFC 3394 takes whole 64 bit blocks and at least two of them. It
    refuses rather than padding, because a wrap that pads and an unwrap
    that does not are the same bytes with different lengths."""
    kek = bytes(range(16))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.key_wrap(kek, bytes(length))


def test_a_64_bit_block_cipher_is_refused():
    """Key wrap is defined over a 128 bit block and there is no 64 bit
    variant to fall back to, so naming one is an error rather than
    something that produces plausible bytes."""
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.key_wrap(bytes(8), bytes(16), cipher="des")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.key_wrap(bytes(32), bytes(16), cipher="magma")


def test_another_128_bit_cipher_works():
    """The mode is generic, as everything else here is: any 128 bit block
    cipher can wrap. Camellia and SM4 have no key wrap of their own
    anywhere, which is exactly why a generic mode is worth having."""
    data = bytes(range(32))
    for cipher, key in [("camellia", bytes(range(16))), ("sm4", bytes(range(16))),
                        ("kuznyechik", bytes(range(32)))]:
        wrapped = allcrypt.key_wrap(key, data, cipher=cipher)
        assert len(wrapped) == len(data) + 8
        assert allcrypt.key_unwrap(key, wrapped, cipher=cipher) == data
        # And it is not AES's answer.
        assert wrapped != allcrypt.key_wrap(bytes(range(16)), data)


def test_a_round_trip_through_every_wrapped_key_length():
    kek = bytes(range(32))
    for length in range(16, 129, 8):
        data = bytes((i * 17) % 256 for i in range(length))
        assert allcrypt.key_unwrap(kek, allcrypt.key_wrap(kek, data)) == data
