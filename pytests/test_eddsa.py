"""EdDSA against python-cryptography, which is OpenSSL underneath.

The Rust unit tests already run every pure vector in RFC 8032 section 7,
read out of the vendored RFC rather than typed. What they cannot do is
notice a mistake the RFC's vectors happen not to exercise, so this file
is the differential half: several hundred signatures over messages of
every length across the interesting boundaries, each one produced by one
implementation and verified by the other, **in both directions**.

The direction matters. A signer and a verifier that share a mistake agree
perfectly with each other, which is what makes a round trip against
oneself worth nothing here:

  * the scalar is the *hash* of the private key, clamped - signing with
    the raw key bytes gives well-formed signatures that verify against
    any implementation that makes the same mistake;
  * everything is little-endian, where the rest of this library is big;
  * Ed448 prefixes its `r` and `k` hashes with `dom4` and its key
    expansion with nothing, and applying `dom4` to all three (which is
    what this library did first) gives a self-consistent Ed448 with the
    wrong public key for every private key.

So every test here has OpenSSL on one side of the comparison.
"""

import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey, Ed448PublicKey)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

import allcrypt


CURVES = {
    "ed25519": (Ed25519PrivateKey, Ed25519PublicKey, 32),
    "ed448": (Ed448PrivateKey, Ed448PublicKey, 57),
}


def raw_private(key):
    return key.private_bytes(serialization.Encoding.Raw,
                             serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())


def raw_public(key):
    if hasattr(key, "public_key"):
        key = key.public_key()
    return key.public_bytes(serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw)


def test_the_curves_are_listed():
    assert allcrypt.eddsa_curves() == ["ed25519", "ed448"]


@pytest.mark.parametrize("name", sorted(CURVES))
def test_key_lengths(name):
    private, public = allcrypt.eddsa_generate(name)
    expected = CURVES[name][2]
    assert len(private) == expected
    assert len(public) == expected


@pytest.mark.parametrize("name", sorted(CURVES))
def test_the_public_key_matches_openssls(name):
    """The key expansion, which is the single easiest thing to get wrong
    and the only one that shows before a signature is made."""
    private_cls = CURVES[name][0]
    for _ in range(16):
        theirs = private_cls.generate()
        ours = allcrypt.eddsa_public_key(name, raw_private(theirs))
        assert ours == raw_public(theirs)


@pytest.mark.parametrize("name", sorted(CURVES))
def test_openssl_verifies_what_we_sign(name):
    """Message lengths across every boundary that matters: the hash's
    block size, the point and scalar widths, and a few beyond.

    A signature is over a hash of the message, so a length that never
    crosses a block boundary cannot see a padding mistake - the same
    class of bug as the SHA-1 length field in this library's history."""
    private_cls, public_cls, _ = CURVES[name]
    theirs = private_cls.generate()
    private = raw_private(theirs)
    public = theirs.public_key()

    lengths = list(range(0, 8)) + [31, 32, 33, 55, 56, 57, 63, 64, 65,
                                   71, 72, 111, 112, 113, 114, 127, 128,
                                   129, 135, 136, 137, 255, 256, 1023]
    for length in lengths:
        message = bytes((i * 7 + length) % 256 for i in range(length))
        signature = allcrypt.eddsa_sign(name, private, message)
        assert len(signature) == 2 * CURVES[name][2]
        # Raises InvalidSignature if it disagrees.
        public.verify(signature, message)


@pytest.mark.parametrize("name", sorted(CURVES))
def test_we_verify_what_openssl_signs(name):
    """The other direction. A verifier can be wrong in ways a signer is
    not - the S-is-reduced check, the point decoding, which half of the
    signature is which - and none of them show when it only ever sees
    its own output."""
    private_cls = CURVES[name][0]
    for length in [0, 1, 2, 31, 32, 63, 64, 113, 114, 200, 1023]:
        theirs = private_cls.generate()
        public = raw_public(theirs)
        message = bytes((i * 11 + length) % 256 for i in range(length))
        signature = theirs.sign(message)
        assert allcrypt.eddsa_verify(name, public, message, signature)


@pytest.mark.parametrize("name", sorted(CURVES))
def test_the_signature_is_the_same_bytes_openssl_produces(name):
    """EdDSA is deterministic, so this is a stronger statement than
    mutual verification: the same key and message must give the *same*
    signature, not merely an acceptable one.

    Only a deterministic scheme allows this. It is here because it is the
    one comparison that a shared misunderstanding of the encoding cannot
    survive."""
    private_cls = CURVES[name][0]
    for length in [0, 1, 17, 64, 65, 500]:
        theirs = private_cls.generate()
        private = raw_private(theirs)
        message = bytes(range(length % 256)) * (length // 256 + 1)
        message = message[:length]
        assert allcrypt.eddsa_sign(name, private, message) == theirs.sign(message)


@pytest.mark.parametrize("name", sorted(CURVES))
def test_a_tampered_message_is_refused(name):
    private, public = allcrypt.eddsa_generate(name)
    message = b"the message that was signed"
    signature = allcrypt.eddsa_sign(name, private, message)
    assert allcrypt.eddsa_verify(name, public, message, signature)
    assert not allcrypt.eddsa_verify(name, public, message + b"!", signature)
    assert not allcrypt.eddsa_verify(name, public, b"", signature)


@pytest.mark.parametrize("name", sorted(CURVES))
def test_a_tampered_signature_is_refused(name):
    private, public = allcrypt.eddsa_generate(name)
    message = b"tamper"
    signature = allcrypt.eddsa_sign(name, private, message)
    for index in range(len(signature)):
        broken = bytearray(signature)
        broken[index] ^= 1 << (index % 8)
        try:
            assert not allcrypt.eddsa_verify(name, public, message, bytes(broken))
        except ValueError:
            # A flipped bit can also make R fail to decode, which is an
            # error rather than a false - either way it is refused.
            pass


@pytest.mark.parametrize("name", sorted(CURVES))
def test_another_key_does_not_verify(name):
    private, _ = allcrypt.eddsa_generate(name)
    _, other = allcrypt.eddsa_generate(name)
    message = b"whose signature is this"
    signature = allcrypt.eddsa_sign(name, private, message)
    assert not allcrypt.eddsa_verify(name, other, message, signature)


def test_the_ed448_context_changes_the_signature():
    """Ed448's context is a domain separator: the same key and message
    under two contexts must give two different signatures, and neither
    may verify under the other's context.

    OpenSSL's Ed448 has no context API through python-cryptography, so
    the RFC's own context vector (in the Rust tests) is the independent
    check and this is the property one."""
    private, public = allcrypt.eddsa_generate("ed448")
    message = b"same message"
    plain = allcrypt.eddsa_sign("ed448", private, message)
    foo = allcrypt.eddsa_sign("ed448", private, message, b"foo")
    bar = allcrypt.eddsa_sign("ed448", private, message, b"bar")

    assert len({plain, foo, bar}) == 3
    assert allcrypt.eddsa_verify("ed448", public, message, foo, b"foo")
    assert not allcrypt.eddsa_verify("ed448", public, message, foo, b"bar")
    assert not allcrypt.eddsa_verify("ed448", public, message, foo)
    assert not allcrypt.eddsa_verify("ed448", public, message, plain, b"foo")


def test_ed25519_has_no_context():
    """Ed25519ctx is a different scheme. Accepting a context here and
    quietly ignoring it would make its signatures look like Ed25519's."""
    private, public = allcrypt.eddsa_generate("ed25519")
    signature = allcrypt.eddsa_sign("ed25519", private, b"x")
    with pytest.raises(ValueError):
        allcrypt.eddsa_sign("ed25519", private, b"x", b"ctx")
    with pytest.raises(ValueError):
        allcrypt.eddsa_verify("ed25519", public, b"x", signature, b"ctx")


@pytest.mark.parametrize("name", ["ed25519ctx", "ed25519ph", "ed448ph"])
def test_the_prehashed_and_context_variants_are_refused_by_name(name):
    """Not aliases. They are different schemes over the same curves, and
    the error says so rather than saying the curve is unknown."""
    with pytest.raises(ValueError) as caught:
        allcrypt.eddsa_generate(name)
    assert "different scheme" in str(caught.value)


def test_an_unknown_curve_is_refused():
    with pytest.raises(ValueError):
        allcrypt.eddsa_generate("ed12345")


@pytest.mark.parametrize("name", sorted(CURVES))
def test_wrong_lengths_are_refused(name):
    length = CURVES[name][2]
    private, public = allcrypt.eddsa_generate(name)
    message = b"x"
    signature = allcrypt.eddsa_sign(name, private, message)

    for bad in [length - 1, length + 1, 0]:
        with pytest.raises(ValueError):
            allcrypt.eddsa_public_key(name, bytes(bad))
        with pytest.raises(ValueError):
            allcrypt.eddsa_verify(name, bytes(bad), message, signature)
    with pytest.raises(ValueError):
        allcrypt.eddsa_verify(name, public, message, signature[:-1])
    with pytest.raises(ValueError):
        allcrypt.eddsa_verify(name, public, message, signature + b"\x00")


@pytest.mark.parametrize("name", sorted(CURVES))
def test_an_unreduced_s_is_refused(name):
    """RFC 8032 section 5.1.7. Adding the group order to a valid S gives
    a second signature satisfying the verification equation, so a
    verifier that does not check gives every message two signatures -
    which has broken systems that used a signature as an identifier.

    OpenSSL refuses it too, and the test asserts that, so this is a
    comparison rather than a claim about our own behaviour."""
    orders = {
        "ed25519": 2 ** 252 + 27742317777372353535851937790883648493,
        "ed448": 2 ** 446
        - 13818066809895115352007386748515426880336692474882178609894547503885,
    }
    length = CURVES[name][2]
    private, public = allcrypt.eddsa_generate(name)
    message = b"malleability"
    signature = allcrypt.eddsa_sign(name, private, message)
    assert allcrypt.eddsa_verify(name, public, message, signature)

    s = int.from_bytes(signature[length:], "little")
    bumped = (s + orders[name]).to_bytes(length, "little")
    malleable = signature[:length] + bumped
    assert not allcrypt.eddsa_verify(name, public, message, malleable)

    their_public = CURVES[name][1].from_public_bytes(public)
    with pytest.raises(InvalidSignature):
        their_public.verify(malleable, message)


@pytest.mark.parametrize("name", sorted(CURVES))
def test_a_public_key_that_is_not_a_point_is_an_error_not_a_false(name):
    """`False` means "this signature is wrong"; a key that is not a point
    is not a statement about the signature at all, and collapsing the two
    is how a caller ends up reporting a forgery for a configuration
    mistake."""
    length = CURVES[name][2]
    private, _ = allcrypt.eddsa_generate(name)
    signature = allcrypt.eddsa_sign(name, private, b"x")

    # Search for a y that is on no point: about half of them are not.
    for candidate in range(256):
        bad = bytes([candidate]) + bytes(length - 1)
        try:
            allcrypt.eddsa_verify(name, bad, b"x", signature)
        except ValueError:
            return
    pytest.fail("no non-point found in 256 tries, which cannot happen")


@pytest.mark.parametrize("name", sorted(CURVES))
def test_signing_is_deterministic(name):
    private, _ = allcrypt.eddsa_generate(name)
    first = allcrypt.eddsa_sign(name, private, b"same")
    second = allcrypt.eddsa_sign(name, private, b"same")
    assert first == second


@pytest.mark.parametrize("name", sorted(CURVES))
def test_the_private_key_is_not_stored_clamped(name):
    """X25519 stores a clamped private key; EdDSA must not, because the
    clamping happens to the *hash* of these bytes. Storing them clamped
    would change which key it is, and the public key would then not match
    the one OpenSSL derives from the same file."""
    private_cls = CURVES[name][0]
    for _ in range(32):
        theirs = private_cls.generate()
        private = raw_private(theirs)
        # A clamped Ed25519 scalar has its low three bits clear; a
        # clamped Ed448 one its low two. Over 32 keys at least one must
        # have them set, or clamping is being applied.
        if private[0] & 0x07:
            assert allcrypt.eddsa_public_key(name, private) == raw_public(theirs)
            return
    pytest.fail("32 generated keys all had clear low bits, which cannot happen")


# ------------------------------------------- small order points and cofactor ---

def test_a_small_order_public_key_is_accepted_as_openssl_accepts_it():
    """**Ed25519 has cofactor 8 and this library does no subgroup check**,
    which means the identity is accepted as a public key and a signature
    under it verifies for every message.

    Nobody holds a private key for it, so this forges nothing that was
    not already public - but it does mean "this signature verifies" is
    not on its own a statement that any particular party signed. A
    protocol that treats a caller-supplied public key as an identity
    needs to reject small-order keys itself.

    RFC 8032 permits either the cofactored equation
    (``[8]S*B = [8]R + [8]k*A``) or the cofactorless one this uses, and
    requires no subgroup check. **OpenSSL behaves the same way**, which
    is asserted here rather than assumed: this test is a record of a
    deliberate choice to match the reference rather than an oversight,
    and it fails if either side changes its mind.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    # The identity, (0, 1), encoded: y = 1 little endian, x's low bit
    # clear. It has order 1, so k*A is the identity for every k.
    identity = (1).to_bytes(32, "little")
    # R = identity and S = 0 makes both sides of S*B == R + k*A the
    # identity, whatever the message is.
    signature = identity + bytes(32)

    assert allcrypt.eddsa_verify("ed25519", identity, b"anything", signature)
    assert allcrypt.eddsa_verify("ed25519", identity, b"a different message",
                                 signature)

    theirs = Ed25519PublicKey.from_public_bytes(identity)
    try:
        theirs.verify(signature, b"anything")
    except InvalidSignature:                                    # pragma: no cover
        pytest.fail(
            "OpenSSL now rejects a small-order Ed25519 key. This library "
            "matched it deliberately; revisit that choice rather than this "
            "assertion.")

    # It is not that *everything* verifies: a real key still refuses a
    # signature that is not its own.
    private, public = allcrypt.eddsa_generate("ed25519")
    assert not allcrypt.eddsa_verify("ed25519", public, b"anything", signature)


def test_a_real_signature_is_still_bound_to_its_key_and_message():
    """The property the test above must not be read as weakening."""
    first_private, first_public = allcrypt.eddsa_generate("ed25519")
    second_private, second_public = allcrypt.eddsa_generate("ed25519")

    signature = allcrypt.eddsa_sign("ed25519", first_private, b"the message")
    assert allcrypt.eddsa_verify("ed25519", first_public, b"the message", signature)
    assert not allcrypt.eddsa_verify("ed25519", second_public, b"the message",
                                     signature)
    assert not allcrypt.eddsa_verify("ed25519", first_public, b"another", signature)
    assert signature != allcrypt.eddsa_sign("ed25519", second_private, b"the message")
