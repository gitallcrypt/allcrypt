"""X25519 against the RFC 7748 vectors and against OpenSSL.

Three things about this curve are different from every other one in the
library, and each is a way to build something that agrees with itself and
with nobody else:

  * the scalar is clamped before use;
  * everything is little-endian, where the rest of this library is big;
  * there is no point validation, because every 32 byte string is a valid
    u coordinate - the check that replaces it is the all-zero output test.

A round-trip test passes with any of those wrong. The published vectors and
the comparison with OpenSSL are what make this testing rather than
agreeing with oneself.
"""

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)

import allcrypt


def raw_public(key):
    """The 32 raw bytes of a key's public half, from a private or a public
    key object - `cryptography` needs a different call for each."""
    if isinstance(key, X25519PrivateKey):
        key = key.public_key()
    return key.public_bytes(serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw)


def test_the_rfc_7748_scalar_multiplication_vectors():
    """RFC 7748 section 5.2. Stated in terms of the raw primitive, which is
    why the binding exposes it separately from the key exchange."""
    for scalar, point, want in [
        ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
         "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
        ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
         "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
         "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
    ]:
        got = allcrypt.x25519_raw(bytes.fromhex(scalar), bytes.fromhex(point))
        assert got.hex() == want


def test_the_rfc_7748_key_exchange_vector():
    """Section 6.1, which pins the public keys as well as the secret - so
    it catches a byte-order mistake that the section 5.2 vectors alone
    would not."""
    alice = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")

    assert allcrypt.x25519_public_key(alice).hex() == (
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    assert allcrypt.x25519_public_key(bob).hex() == (
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")

    shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert allcrypt.x25519_exchange(
        alice, allcrypt.x25519_public_key(bob)).hex() == shared
    assert allcrypt.x25519_exchange(
        bob, allcrypt.x25519_public_key(alice)).hex() == shared


@pytest.mark.parametrize("trial", range(20))
def test_agreement_with_openssl_in_both_directions(trial):
    """Ours against theirs and theirs against ours. One direction alone
    would pass if we derived public keys wrongly but consistently."""
    our_private, our_public = allcrypt.x25519_generate()
    their_private = X25519PrivateKey.generate()

    assert allcrypt.x25519_public_key(our_private) == our_public
    assert raw_public(X25519PrivateKey.from_private_bytes(our_private)) == our_public

    ours = allcrypt.x25519_exchange(our_private, raw_public(their_private))
    theirs = their_private.exchange(X25519PublicKey.from_public_bytes(our_public))
    assert ours == theirs
    assert len(ours) == 32


def test_an_unclamped_private_key_is_clamped_before_use():
    """Clamping is visible: the same bytes used unclamped give a different
    public key. OpenSSL clamps too, so agreeing with it is the test - an
    implementation that skips clamping agrees only with itself."""
    raw = bytes([0xff] * 32)
    ours = allcrypt.x25519_public_key(raw)
    assert ours == raw_public(X25519PrivateKey.from_private_bytes(raw))

    # And the clamped scalar is a different number from the raw one, so
    # this is not a no-op that happens to agree.
    clamped = bytearray(raw)
    clamped[0] &= 248
    clamped[31] = (clamped[31] & 127) | 64
    assert bytes(clamped) != raw
    assert allcrypt.x25519_public_key(bytes(clamped)) == ours


@pytest.mark.parametrize("point", [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
])
def test_low_order_points_are_refused(point):
    """Each of these makes the shared secret all zero - a constant every
    observer can compute. RFC 7748 section 6.1 makes the check optional;
    an optional check against an active attacker is not a check.

    `cryptography` refuses these too, which is the independent
    confirmation that they are what this test says they are.
    """
    private, _public = allcrypt.x25519_generate()
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.x25519_exchange(private, bytes.fromhex(point))

    # The raw primitive still computes: the refusal belongs to the key
    # exchange, not to the arithmetic.
    assert allcrypt.x25519_raw(private, bytes.fromhex(point)) == bytes(32)


def test_a_non_canonical_u_coordinate_is_masked_not_refused():
    """RFC 7748 says the top bit of the u coordinate is ignored. Refusing
    it instead would break a handshake with a peer doing exactly what the
    specification says - and OpenSSL is such a peer."""
    private, _ = allcrypt.x25519_generate()
    peer = allcrypt.x25519_public_key(bytes([7] * 32))
    plain = allcrypt.x25519_exchange(private, peer)

    with_high_bit = bytearray(peer)
    with_high_bit[31] |= 0x80
    assert allcrypt.x25519_exchange(private, bytes(with_high_bit)) == plain


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_wrong_lengths_are_refused(length):
    """32 bytes, both sides. The length is the only thing about an X25519
    value that can be wrong, so it is the one thing worth checking."""
    private, public = allcrypt.x25519_generate()
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.x25519_exchange(bytes(length), public)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.x25519_exchange(private, bytes(length))
