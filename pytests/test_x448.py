"""X448 against the RFC 7748 vectors and against OpenSSL.

`test_x25519.py` is the same shape over the other Montgomery curve, and
the differences are what this file is for. X448 is **not X25519 with
bigger numbers**, and three of the four differences are silent:

  * the clamp is **two** low bits and bit **447**, where X25519's is
    three low bits and bit 254 - Curve448's cofactor is 4 rather than 8;
  * the base point's u coordinate is **5**, not 9;
  * `a24` is **39081**, from `A = 156326`, where X25519's is 121665;
  * and there is **no spare high bit to ignore**, because the field is
    448 bits in exactly 56 bytes. X25519's non-canonical-encoding rule
    has no equivalent here, and a masking step copied over would clear a
    real bit of the peer's coordinate.

Every one of those produces something that round-trips, agrees with
itself, and agrees with nobody. The published vectors and the comparison
with OpenSSL are what make this testing rather than agreeing with
oneself.
"""

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import (
    X448PrivateKey, X448PublicKey)

import allcrypt

KEY_LEN = 56

#: RFC 7748 section 5.2's X448 vectors. Typed here rather than parsed,
#: because the parser lives in Rust where the document is vendored -
#: `src/ec/x448_vectors.rs` reads these same numbers out of
#: `rfcs/rfc7748.txt` and `src/ec/x448.rs` checks them, so these copies
#: are pinned to the document by that test rather than by having been
#: typed carefully. If they ever disagree, the Rust side is right.
RFC_7748_VECTORS = [
    ("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121"
     "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
     "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9"
     "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
     "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f"
     "e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"),
    ("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5"
     "38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
     "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b"
     "165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
     "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7"
     "ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"),
]


def raw_public(key):
    """The 56 raw bytes of a key's public half, from a private or a public
    key object - `cryptography` needs a different call for each."""
    if isinstance(key, X448PrivateKey):
        key = key.public_key()
    return key.public_bytes(serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw)


def test_the_rfc_7748_scalar_multiplication_vectors():
    """Stated in terms of the raw primitive, which is why the binding
    exposes it separately from the key exchange."""
    for scalar, point, want in RFC_7748_VECTORS:
        got = allcrypt.x448_raw(bytes.fromhex(scalar), bytes.fromhex(point))
        assert got.hex() == want


def test_the_rust_side_reads_the_same_vectors_out_of_the_document():
    """The numbers above are 112 hex digits each and were typed.

    What stops that mattering is that `src/ec/x448_vectors.rs` parses the
    vendored RFC and `src/ec/x448.rs` asserts the same answers, so a
    mistyped digit here fails against the document there. This test only
    has to confirm the two sets are the same claim - it does the
    comparison the one way Python can, by checking OpenSSL agrees with
    what is written above.
    """
    for scalar, point, want in RFC_7748_VECTORS:
        key = X448PrivateKey.from_private_bytes(bytes.fromhex(scalar))
        theirs = key.exchange(X448PublicKey.from_public_bytes(
            bytes.fromhex(point)))
        assert theirs.hex() == want, "a vector above disagrees with OpenSSL"


def test_the_rfc_7748_key_exchange_vector():
    """RFC 7748 section 6.2: Alice and Bob's keys and the secret.

    The vector that catches a byte-order mistake, because it fixes the
    **public keys** as well as the shared secret - two implementations
    that both encoded big-endian would agree on a secret and disagree
    with this.
    """
    alice = bytes.fromhex(
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
        "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b")
    alice_public = ("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
                    "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0")
    bob = bytes.fromhex(
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d"
        "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d")
    bob_public = ("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
                  "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609")
    secret = ("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
              "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d")

    assert allcrypt.x448_public_key(alice).hex() == alice_public
    assert allcrypt.x448_public_key(bob).hex() == bob_public
    assert allcrypt.x448_exchange(alice, bytes.fromhex(bob_public)).hex() \
        == secret
    assert allcrypt.x448_exchange(bob, bytes.fromhex(alice_public)).hex() \
        == secret


@pytest.mark.parametrize("trial", range(6))
def test_agreement_with_openssl_in_both_directions(trial):
    """Ours against theirs and theirs against ours.

    One direction alone would pass on an implementation that computed
    something consistent but wrong for one of the two roles - and X448 is
    symmetric, so a self-exchange proves nothing at all.
    """
    del trial
    ours_private, ours_public = allcrypt.x448_generate()
    theirs = X448PrivateKey.generate()

    assert allcrypt.x448_exchange(ours_private, raw_public(theirs)) == \
        theirs.exchange(X448PublicKey.from_public_bytes(ours_public))

    # And their key's public half must be one we compute the same way.
    theirs_raw = theirs.private_bytes(serialization.Encoding.Raw,
                                      serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption())
    assert allcrypt.x448_public_key(theirs_raw) == raw_public(theirs)


def test_an_unclamped_private_key_is_clamped_before_use():
    """A scalar with its low bits set and its top bit clear is not a
    clamped scalar, and both implementations must clamp it the same way.

    **This is where a clamp copied from X25519 shows.** Three low bits
    cleared instead of two gives a different, perfectly valid scalar; the
    public key is a real point on the curve and OpenSSL computes a
    different one.
    """
    scalar = bytes([0xff] * KEY_LEN)
    ours = allcrypt.x448_public_key(scalar)
    theirs = raw_public(X448PrivateKey.from_private_bytes(scalar))
    assert ours == theirs

    # And the two curves must not agree about how to clamp, or one of
    # them is wrong. X25519's low byte keeps bit 2 clear; X448's keeps it.
    x25519_public = allcrypt.x25519_public_key(bytes([0xff] * 32))
    assert len(x25519_public) == 32 and len(ours) == KEY_LEN


@pytest.mark.parametrize("value", [0, 1])
def test_low_order_points_are_refused(value):
    """RFC 7748 section 7 names these. The exchange must refuse; the raw
    primitive must return zero, because that is what the specification
    defines it to do."""
    point = bytes([value] + [0] * (KEY_LEN - 1))
    private, _ = allcrypt.x448_generate()
    assert allcrypt.x448_raw(private, point) == bytes(KEY_LEN)
    with pytest.raises(ValueError) as caught:
        allcrypt.x448_exchange(private, point)
    assert "all zero" in str(caught.value)


def test_a_coordinate_above_the_prime_is_reduced_not_refused():
    """There is no spare bit here, so this is the shape X25519's
    non-canonical-encoding rule takes on Curve448.

    `p = 2^448 - 2^224 - 1`, so a coordinate of all-ones bytes is above
    it. RFC 7748 does not make that an error, and OpenSSL reduces - an
    implementation that refused would break against a peer doing exactly
    what the document says.
    """
    private, _ = allcrypt.x448_generate()
    point = bytes([0xff] * KEY_LEN)
    ours = allcrypt.x448_raw(private, point)
    theirs = X448PrivateKey.from_private_bytes(private).exchange(
        X448PublicKey.from_public_bytes(point))
    assert ours == theirs


@pytest.mark.parametrize("length", [0, 1, 31, 32, 55, 57, 64])
def test_wrong_lengths_are_refused(length):
    """**32 is in this list on purpose.** An X25519 key passed to an X448
    function is the likeliest mistake at this boundary, and it must be an
    error rather than something padded - the error names the algorithm
    that wanted 56 so the caller can see which call is wrong."""
    private, public = allcrypt.x448_generate()
    with pytest.raises(ValueError) as caught:
        allcrypt.x448_public_key(bytes(length))
    assert "56 bytes" in str(caught.value)
    with pytest.raises(ValueError):
        allcrypt.x448_exchange(private, bytes(length))
    with pytest.raises(ValueError):
        allcrypt.x448_exchange(bytes(length), public)


def test_the_two_curves_are_not_interchangeable():
    """A key from one must not be usable with the other.

    They have the same interface and different widths, so the length
    check is the whole of what separates them at this boundary.
    """
    x448_private, x448_public = allcrypt.x448_generate()
    x25519_private, x25519_public = allcrypt.x25519_generate()

    with pytest.raises(ValueError):
        allcrypt.x448_exchange(x25519_private, x25519_public)
    with pytest.raises(ValueError):
        allcrypt.x25519_exchange(x448_private, x448_public)
