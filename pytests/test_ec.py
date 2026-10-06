"""Elliptic curve bindings, checked against OpenSSL through `cryptography`.

The Rust suite proves the curve arithmetic (the unit tests in src/ec/mod.rs
and tools/src/bin/diff_ec.rs, 324 cases against OpenSSL). What these tests add is the
binding layer: that a key generated here interoperates with a real TLS
implementation in both directions, that the SEC1 bytes are the bytes OpenSSL
expects, and that a bad peer point raises instead of returning a secret.
"""

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import allcrypt

# Our names against the `cryptography` curve objects.
REFERENCE = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
    "secp256k1": ec.SECP256K1(),
}

# P-521's 66, not 65: 521 bits is eight 64 bit limbs and one bit, and a
# width computed as bits / 8 is one byte short.
FIELD_BYTES = {"P-256": 32, "P-384": 48, "P-521": 66, "secp256k1": 32}

# The curves `cryptography` cannot give us an object for, so the rest of
# this file cannot compare them against anything. Listed rather than
# inferred: a curve appearing or disappearing should be a test failure,
# and "everything not in REFERENCE" would quietly absorb either.
#
# The GOST seven are in no OpenSSL build here at all. **sm2p256v1 is
# different**: this OpenSSL has the curve and implements SM2 on it, but
# `cryptography` refuses to load a key on it ("Curve 1.2.156.10197.1.301
# is not supported"), so it cannot be reached through this file's
# reference. It is checked in `pytests/test_sm2.py` against the
# `openssl` binary instead, in both directions, and by the `sm2p256v1`
# rows in `scripts/diff_check.py`.
NO_REFERENCE = {"gost256-a", "gost256-b", "gost256-c", "gost256-tc26-a",
                "gost512-a", "gost512-b", "gost512-c", "sm2p256v1"}


def ref_encode(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def ref_public_from_bytes(name, encoded):
    return ec.EllipticCurvePublicKey.from_encoded_point(REFERENCE[name], encoded)


def test_curves_available_is_what_it_says():
    """Every curve is either one OpenSSL also has - and the rest of this
    file compares those against it - or one named in `NO_REFERENCE` with
    its own checks elsewhere. Neither set may grow silently."""
    assert set(allcrypt.curves_available) == set(REFERENCE) | NO_REFERENCE
    assert not set(REFERENCE) & NO_REFERENCE
    for name in allcrypt.curves_available:
        assert allcrypt.EcKey.generate(name).curve == name


@pytest.mark.parametrize("name", sorted(REFERENCE))
def test_generated_key_is_valid_to_openssl(name):
    """OpenSSL refuses a point that is not on the curve, so this is a real
    check that our generator produces genuine public keys."""
    key = allcrypt.EcKey.generate(name)
    # The curve's size as OpenSSL reports it: 521 for P-521, not the
    # 528 its 66 byte encodings would suggest.
    assert key.key_size == REFERENCE[name].key_size

    uncompressed = key.public_bytes()
    compressed = key.public_bytes(compressed=True)
    assert len(uncompressed) == 1 + 2 * FIELD_BYTES[name]
    assert len(compressed) == 1 + FIELD_BYTES[name]
    assert uncompressed[0] == 0x04
    assert compressed[0] in (0x02, 0x03)

    # Both encodings must decode to the same point on OpenSSL's side.
    a = ref_public_from_bytes(name, uncompressed)
    b = ref_public_from_bytes(name, compressed)
    assert a.public_numbers() == b.public_numbers()


@pytest.mark.parametrize("name", sorted(REFERENCE))
def test_public_key_matches_openssl_for_the_same_scalar(name):
    """Import the same private scalar on both sides; the public points must
    agree. This is the one test that would catch a scalar multiplication
    that is wrong in a way that is still self-consistent."""
    key = allcrypt.EcKey.generate(name)
    scalar = int.from_bytes(key.private_bytes(), "big")

    reference = ec.derive_private_key(scalar, REFERENCE[name])
    want = ref_encode(reference.public_key())
    assert key.public_bytes() == want


@pytest.mark.parametrize("name", sorted(REFERENCE))
def test_ecdh_against_openssl(name):
    """The shared secret must match in both directions: our key against
    theirs, and theirs against ours."""
    ours = allcrypt.EcKey.generate(name)
    theirs = ec.generate_private_key(REFERENCE[name])

    their_public = ref_encode(theirs.public_key())

    ours_says = ours.exchange(their_public)
    theirs_says = theirs.exchange(ec.ECDH(), ref_public_from_bytes(name, ours.public_bytes()))

    assert ours_says == theirs_says
    assert len(ours_says) == FIELD_BYTES[name]

    # And the compressed form of our point must produce the same secret.
    theirs_compressed = theirs.exchange(
        ec.ECDH(), ref_public_from_bytes(name, ours.public_bytes(compressed=True)))
    assert theirs_compressed == ours_says


@pytest.mark.parametrize("name", sorted(REFERENCE))
def test_round_trip_through_from_private(name):
    key = allcrypt.EcKey.generate(name)
    again = allcrypt.EcKey.from_private(name, key.private_bytes())
    assert again.private_bytes() == key.private_bytes()
    assert again.public_bytes() == key.public_bytes()
    assert again.curve == name


@pytest.mark.parametrize("name", sorted(REFERENCE))
def test_two_keys_are_different(name):
    """A generator that is stuck would still pass every test above."""
    seen = {allcrypt.EcKey.generate(name).private_bytes() for _ in range(8)}
    assert len(seen) == 8


def test_unknown_curve_raises():
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.EcKey.generate("brainpoolP256r1")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.EcKey.from_private("curve25519", b"\x01" * 32)


@pytest.mark.parametrize("name", sorted(REFERENCE))
def test_bad_scalars_raise(name):
    n = REFERENCE[name].key_size  # bits; only used for a plausible length
    size = FIELD_BYTES[name]
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.EcKey.from_private(name, bytes(size))      # zero
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.EcKey.from_private(name, b"\xff" * size)   # above n
    assert n  # the parameter is there to document the shape


@pytest.mark.parametrize("name", sorted(REFERENCE))
def test_invalid_peer_point_raises(name):
    """An attacker who sends a point on a weaker curve learns the private
    scalar modulo that curve's small order if we multiply blindly. Every
    peer point is validated first, so this must raise."""
    ours = allcrypt.EcKey.generate(name)
    theirs = allcrypt.EcKey.generate(name)

    good = bytearray(theirs.public_bytes())
    assert ours.exchange(bytes(good))  # sanity: the unmodified point works

    off_curve = bytearray(good)
    off_curve[-1] ^= 0x01
    with pytest.raises(allcrypt.CryptoError):
        ours.exchange(bytes(off_curve))

    with pytest.raises(allcrypt.CryptoError):
        ours.exchange(b"\x04")                       # truncated
    with pytest.raises(allcrypt.CryptoError):
        ours.exchange(b"\x00" * len(good))           # bad prefix byte
    with pytest.raises(allcrypt.CryptoError):
        ours.exchange(bytes(good) + b"\x00")         # trailing junk
    with pytest.raises(allcrypt.CryptoError):
        ours.exchange(b"")                           # empty


def test_cross_curve_point_is_rejected():
    """A P-256 point offered to a P-384 key is the invalid-curve attack in
    its simplest form; the length check alone catches this one, but it is
    worth pinning."""
    p384 = allcrypt.EcKey.generate("P-384")
    p256 = allcrypt.EcKey.generate("P-256")
    with pytest.raises(allcrypt.CryptoError):
        p384.exchange(p256.public_bytes())
    with pytest.raises(allcrypt.CryptoError):
        p256.exchange(p384.public_bytes())

    # secp256k1 and P-256 share a field size, so the length check cannot
    # save us here: this one is caught by the on-curve test, which is the
    # part that actually matters.
    k1 = allcrypt.EcKey.generate("secp256k1")
    with pytest.raises(allcrypt.CryptoError):
        p256.exchange(k1.public_bytes())
    with pytest.raises(allcrypt.CryptoError):
        k1.exchange(p256.public_bytes())


# ------------------------------------------------------------------ ECDSA ---

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

HASHES = {"sha1": hashes.SHA1(), "sha224": hashes.SHA224(),
          "sha256": hashes.SHA256(), "sha384": hashes.SHA384(),
          "sha512": hashes.SHA512()}


def our_digest(name, message):
    return allcrypt.new(name, message).digest()


@pytest.mark.parametrize("name", sorted(REFERENCE))
@pytest.mark.parametrize("digestmod", sorted(HASHES))
def test_openssl_accepts_our_signatures(name, digestmod):
    """The direction that matters: a real implementation must accept what we
    produce. Prehashed, because we sign digests rather than messages."""
    key = allcrypt.EcKey.generate(name)
    digest = our_digest(digestmod, b"a message to sign")
    signature = key.sign(digest, digestmod=digestmod)

    assert len(signature) == 2 * FIELD_BYTES[name]
    half = FIELD_BYTES[name]
    r = int.from_bytes(signature[:half], "big")
    s = int.from_bytes(signature[half:], "big")

    public = ref_public_from_bytes(name, key.public_bytes())
    public.verify(asym_utils.encode_dss_signature(r, s), digest,
                  ec.ECDSA(asym_utils.Prehashed(HASHES[digestmod])))


@pytest.mark.parametrize("name", sorted(REFERENCE))
def test_we_accept_openssl_signatures(name):
    """And the other direction, which is what a TLS client actually does."""
    reference = ec.generate_private_key(REFERENCE[name])
    digest = our_digest("sha256", b"signed by openssl")
    der = reference.sign(digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
    r, s = asym_utils.decode_dss_signature(der)

    half = FIELD_BYTES[name]
    signature = r.to_bytes(half, "big") + s.to_bytes(half, "big")

    public = allcrypt.EcPublicKey(name, ref_encode(reference.public_key()))
    assert public.verify(digest, signature)
    assert not public.verify(our_digest("sha256", b"a different message"), signature)


@pytest.mark.parametrize("name", sorted(REFERENCE))
def test_signatures_are_deterministic(name):
    """RFC 6979: no randomness, so the same input gives the same bytes. This
    is the property that makes a repeated nonce impossible."""
    key = allcrypt.EcKey.generate(name)
    digest = our_digest("sha256", b"sign me twice")
    assert key.sign(digest) == key.sign(digest)
    assert key.sign(digest) != key.sign(our_digest("sha256", b"something else"))


def test_rfc6979_vector():
    """RFC 6979 A.2.5, P-256 with SHA-256, key and message from the RFC. If
    any detail of the nonce derivation is wrong these bytes differ."""
    private = bytes.fromhex(
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
    key = allcrypt.EcKey.from_private("P-256", private)
    signature = key.sign(our_digest("sha256", b"sample"), digestmod="sha256")

    assert signature.hex().upper() == (
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")


@pytest.mark.parametrize("name", sorted(REFERENCE))
def test_verification_rejects_tampering(name):
    key = allcrypt.EcKey.generate(name)
    public = key.public_key()
    digest = our_digest("sha256", b"authentic")
    signature = key.sign(digest)

    assert public.verify(digest, signature)
    assert not public.verify(our_digest("sha256", b"forged"), signature)

    # Any single flipped bit must break it.
    for index in (0, len(signature) // 2, len(signature) - 1):
        tampered = bytearray(signature)
        tampered[index] ^= 0x01
        assert not public.verify(digest, bytes(tampered)), f"byte {index}"

    # Halves swapped.
    half = len(signature) // 2
    assert not public.verify(digest, signature[half:] + signature[:half])

    # Zero r or s is not a signature; neither is the wrong length.
    assert not public.verify(digest, bytes(half) + signature[half:])
    assert not public.verify(digest, signature[:half] + bytes(half))
    with pytest.raises(allcrypt.CryptoError):
        public.verify(digest, signature[:-1])
    with pytest.raises(allcrypt.CryptoError):
        public.verify(digest, b"")

    # And another key's signature over the same digest.
    other = allcrypt.EcKey.generate(name)
    assert not public.verify(digest, other.sign(digest))


def test_public_key_import_validates():
    key = allcrypt.EcKey.generate("P-256")
    bad = bytearray(key.public_bytes())
    bad[-1] ^= 1
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.EcPublicKey("P-256", bytes(bad))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.EcPublicKey("P-521", key.public_bytes())

    # A valid point imports, round trips, and keeps its curve.
    public = allcrypt.EcPublicKey("P-256", key.public_bytes(compressed=True))
    assert public.public_bytes() == key.public_bytes()
    assert public.curve == "P-256" and public.key_size == 256


def test_unknown_digestmod_raises():
    key = allcrypt.EcKey.generate("P-256")
    with pytest.raises(allcrypt.CryptoError):
        key.sign(bytes(32), digestmod="md6")
